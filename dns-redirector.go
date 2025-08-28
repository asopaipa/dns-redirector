// Codigo Go para un servidor DNS que redirige IPs con soporte DoT
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// IPBlock representa un bloque de IPs origen que redirige a un conjunto de IPs destino
type IPBlock struct {
	Name        string
	SourceIPs   map[string]bool
	TargetIPs   []net.IP
	Description string
}

// dnsCacheEntry representa una entrada en nuestra caché DNS.
// Guarda el *dns.Msg completo y la hora de expiración.
type dnsCacheEntry struct {
	msg        *dns.Msg
	expiration time.Time
}

// dnsCache almacena un map de entradas cacheadas.
// La clave suele ser "nombre|qtype", por ejemplo "example.com.|1" para A.
type dnsCache struct {
	mu    sync.RWMutex
	store map[string]*dnsCacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		store: make(map[string]*dnsCacheEntry),
	}
}

// IPRedirector gestiona la redirección de DNS basada en múltiples bloques de IPs
type IPRedirector struct {
	blocks          map[string]*IPBlock
	defaultTargetIP net.IP
	mutex           sync.RWMutex
	workerCount     int
	ipBlocksFile    string
	lastModified    time.Time
	reloadInterval  time.Duration
	configFile      string
	configLastMod   time.Time
	stopChan        chan struct{}
	reloadSignal    chan struct{}

	client       *dns.Client
	clientDoT    *dns.Client  // Cliente para DoT upstream
	dnsServer    *dns.Server
	dnsServerTCP *dns.Server
	dnsServerDoT *dns.Server  // Servidor DoT

	// Caché DNS
	cache *dnsCache
	
	// Configuración DoT
	enableDoT      bool
	dotCertFile    string
	dotKeyFile     string
	dotListenAddr  string
	upstreamDoT    string  // Servidor DoT upstream (ej: "1.1.1.1:853")
}

// DNSRequest encapsula una solicitud DNS
type DNSRequest struct {
	W   dns.ResponseWriter
	Req *dns.Msg
}

func NewIPRedirector(ipBlocksFile, configFile string, defaultTargetIP string, workerCount int, reloadInterval time.Duration, enableDoT bool, dotCertFile, dotKeyFile, dotListenAddr, upstreamDoT string) (*IPRedirector, error) {
	redirector := &IPRedirector{
		blocks:          make(map[string]*IPBlock),
		defaultTargetIP: net.ParseIP(defaultTargetIP),
		workerCount:     workerCount,
		ipBlocksFile:    ipBlocksFile,
		reloadInterval:  reloadInterval,
		configFile:      configFile,
		stopChan:        make(chan struct{}),
		reloadSignal:    make(chan struct{}, 1),
		client:          &dns.Client{},
		cache:           newDNSCache(),
		enableDoT:       enableDoT,
		dotCertFile:     dotCertFile,
		dotKeyFile:      dotKeyFile,
		dotListenAddr:   dotListenAddr,
		upstreamDoT:     upstreamDoT,
	}

	if redirector.defaultTargetIP == nil {
		return nil, fmt.Errorf("invalid default target IP: %s", defaultTargetIP)
	}

	// Configurar cliente DoT si está habilitado
	if enableDoT && upstreamDoT != "" {
		redirector.clientDoT = &dns.Client{
			Net: "tcp-tls",
			TLSConfig: &tls.Config{
				ServerName: strings.Split(upstreamDoT, ":")[0], // Extraer hostname para SNI
			},
		}
		log.Printf("DoT client configured for upstream: %s", upstreamDoT)
	}

	// Semilla para números aleatorios (para elegir target IPs de forma aleatoria)
	rand.Seed(time.Now().UnixNano())

	// Carga inicial de bloques de IPs
	err := redirector.loadIPBlocksFromFile()
	if err != nil {
		return nil, err
	}

	// Carga inicial de configuración
	if configFile != "" {
		if err := redirector.loadConfig(); err != nil {
			log.Printf("Warning: Could not load config file: %v", err)
		}
	}

	// Iniciar la monitorización de cambios en archivo
	go redirector.watchFiles()

	// Iniciar limpieza periódica de la caché (opcional, 1 minuto)
	go redirector.startCacheCleaner(1 * time.Minute)

	return redirector, nil
}

func (r *IPRedirector) loadIPBlocksFromFile() error {
	fileInfo, err := os.Stat(r.ipBlocksFile)
	if err != nil {
		return fmt.Errorf("error accessing IP blocks file: %w", err)
	}

	// Verificar si el archivo no ha sido modificado desde la última lectura
	if !fileInfo.ModTime().After(r.lastModified) && !r.lastModified.IsZero() {
		return nil
	}

	file, err := os.Open(r.ipBlocksFile)
	if err != nil {
		return fmt.Errorf("error opening IP blocks file: %w", err)
	}
	defer file.Close()

	newBlocks := make(map[string]*IPBlock)
	scanner := bufio.NewScanner(file)

	var currentBlock *IPBlock

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Nuevo bloque: [BlockName]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			blockName := strings.TrimSpace(strings.Trim(line, "[]"))
			currentBlock = &IPBlock{
				Name:      blockName,
				SourceIPs: make(map[string]bool),
				TargetIPs: []net.IP{},
			}
			newBlocks[blockName] = currentBlock
			continue
		}

		// Si no estamos en un bloque, ignorar la línea
		if currentBlock == nil {
			continue
		}

		// description=...
		if strings.HasPrefix(line, "description=") {
			currentBlock.Description = strings.TrimSpace(strings.TrimPrefix(line, "description="))
			continue
		}

		// target=...
		if strings.HasPrefix(line, "target=") {
			targetIP := strings.TrimSpace(strings.TrimPrefix(line, "target="))
			parsedIP := net.ParseIP(targetIP)
			if parsedIP == nil {
				log.Printf("Warning: Invalid target IP format in block %s: %s, skipping", currentBlock.Name, targetIP)
				continue
			}
			currentBlock.TargetIPs = append(currentBlock.TargetIPs, parsedIP)
			continue
		}

		// Cualquier otra línea, asumimos que es IP origen
		parsedIP := net.ParseIP(line)
		if parsedIP == nil {
			log.Printf("Warning: Invalid source IP format in block %s: %s, skipping", currentBlock.Name, line)
			continue
		}
		currentBlock.SourceIPs[line] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading IP blocks file: %w", err)
	}

	// Actualizar bloques
	r.mutex.Lock()
	r.blocks = newBlocks
	r.lastModified = fileInfo.ModTime()
	r.mutex.Unlock()

	log.Printf("Loaded %d IP blocks from %s (modified: %s)", len(newBlocks), r.ipBlocksFile, fileInfo.ModTime().Format(time.RFC3339))
	for name, block := range newBlocks {
		log.Printf("  Block '%s': %d source IPs, %d target IPs - %s",
			name, len(block.SourceIPs), len(block.TargetIPs), block.Description)
	}

	return nil
}

func (r *IPRedirector) loadConfig() error {
	if r.configFile == "" {
		return nil
	}

	fileInfo, err := os.Stat(r.configFile)
	if err != nil {
		return fmt.Errorf("error accessing config file: %w", err)
	}

	if !fileInfo.ModTime().After(r.configLastMod) && !r.configLastMod.IsZero() {
		return nil
	}

	file, err := os.Open(r.configFile)
	if err != nil {
		return fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		config[key] = value
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	// Comprobar cambios en la IP destino por defecto
	if newDefaultTargetIP, ok := config["DEFAULT_TARGET_IP"]; ok {
		parsedIP := net.ParseIP(newDefaultTargetIP)
		if parsedIP == nil {
			log.Printf("Warning: Invalid default target IP in config: %s, ignoring", newDefaultTargetIP)
		} else {
			r.mutex.Lock()
			oldIP := r.defaultTargetIP.String()
			r.defaultTargetIP = parsedIP
			r.mutex.Unlock()
			log.Printf("Default target IP changed from %s to %s", oldIP, newDefaultTargetIP)
		}
	}

	// Cargar configuración DoT desde archivo de config
	if upstreamDoT, ok := config["UPSTREAM_DOT"]; ok {
		r.mutex.Lock()
		r.upstreamDoT = upstreamDoT
		if r.enableDoT {
			r.clientDoT = &dns.Client{
				Net: "tcp-tls",
				TLSConfig: &tls.Config{
					ServerName: strings.Split(upstreamDoT, ":")[0],
				},
			}
		}
		r.mutex.Unlock()
		log.Printf("DoT upstream server updated to: %s", upstreamDoT)
	}

	r.configLastMod = fileInfo.ModTime()
	log.Printf("Loaded configuration from %s (modified: %s)", r.configFile, fileInfo.ModTime().Format(time.RFC3339))
	return nil
}

func (r *IPRedirector) watchFiles() {
	ticker := time.NewTicker(r.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.loadIPBlocksFromFile(); err != nil {
				log.Printf("Error reloading IP blocks: %v", err)
			}
			if err := r.loadConfig(); err != nil {
				log.Printf("Error reloading config: %v", err)
			}
		case <-r.reloadSignal:
			if err := r.loadIPBlocksFromFile(); err != nil {
				log.Printf("Error reloading IP blocks: %v", err)
			}
			if err := r.loadConfig(); err != nil {
				log.Printf("Error reloading config: %v", err)
			}
		case <-r.stopChan:
			return
		}
	}
}

func (r *IPRedirector) TriggerReload() {
	select {
	case r.reloadSignal <- struct{}{}:
	default:
	}
}

func (r *IPRedirector) Stop() {
	close(r.stopChan)
	if r.dnsServer != nil {
		if err := r.dnsServer.Shutdown(); err != nil {
			log.Printf("Error shutting down DNS server: %v", err)
		}
	}
	if r.dnsServerTCP != nil {
		if err := r.dnsServerTCP.Shutdown(); err != nil {
			log.Printf("Error shutting down DNS TCP server: %v", err)
		}
	}
	if r.dnsServerDoT != nil {
		if err := r.dnsServerDoT.Shutdown(); err != nil {
			log.Printf("Error shutting down DoT server: %v", err)
		}
	}
}

// Método para obtener una IP destino en función de la IP devuelta por upstream
func (r *IPRedirector) getRedirectIP(sourceIP string) (net.IP, string, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for blockName, block := range r.blocks {
		if _, found := block.SourceIPs[sourceIP]; found {
			if len(block.TargetIPs) > 0 {
				randomIdx := rand.Intn(len(block.TargetIPs))
				return block.TargetIPs[randomIdx], blockName, true
			}
			// Si no hay IPs destino en ese bloque, usar la default
			return r.defaultTargetIP, blockName, true
		}
	}

	// Si no hay ningún bloque que coincida
	return r.defaultTargetIP, "default", false
}

// handleDNSRequest con uso de caché y soporte DoT
func (r *IPRedirector) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	// Normalmente, para un forwarder, no somos autoritativos
	msg.Authoritative = false

	var allAnswers []dns.RR

	for _, q := range req.Question {
		// 1. Generar una clave de caché según nombre y tipo
		cacheKey := fmt.Sprintf("%s|%d", q.Name, q.Qtype)

		// 2. Intentar buscar en caché
		cachedResp := r.lookupCache(cacheKey)
		if cachedResp != nil {
			// Añadir todos los RR de la respuesta cacheada
			allAnswers = append(allAnswers, cachedResp.Answer...)
			continue
		}

		// 3. Cache miss -> consultar al upstream
		questionMsg := new(dns.Msg)
		questionMsg.SetQuestion(q.Name, q.Qtype)
		log.Printf("Query for %s (cache miss)", q.Name)

		var resp *dns.Msg
		var err error

		// Decidir si usar DoT o DNS normal para upstream
		if r.enableDoT && r.clientDoT != nil && r.upstreamDoT != "" {
			// Usar DoT para consultar upstream
			resp, _, err = r.clientDoT.Exchange(questionMsg, r.upstreamDoT)
			if err != nil {
				log.Printf("Error querying upstream DoT DNS for %s: %v, falling back to regular DNS", q.Name, err)
				// Fallback a DNS normal si DoT falla
				resp, _, err = r.client.Exchange(questionMsg, "8.8.8.8:53")
			}
		} else {
			// Usar DNS normal
			resp, _, err = r.client.Exchange(questionMsg, "8.8.8.8:53")
		}

		if err != nil {
			log.Printf("Error querying upstream DNS for %s: %v", q.Name, err)
			msg.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(msg)
			return
		}

		// 4. Reescribir registros A si corresponde
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ipStr := a.A.String()
				targetIP, blockName, found := r.getRedirectIP(ipStr)
				if found {
					log.Printf("Redirecting %s from %s to %s (block: %s)",
						q.Name, ipStr, targetIP.String(), blockName)
					a.A = targetIP
				}
			}
			allAnswers = append(allAnswers, ans)
		}

		// 5. Guardar en caché la respuesta
		r.saveCache(cacheKey, resp)
	}

	msg.Answer = allAnswers
	_ = w.WriteMsg(msg)
}

// startDNSServer inicia los servidores DNS (UDP, TCP y DoT si está habilitado)
func (r *IPRedirector) startDNSServer(address string) error {
	requestChan := make(chan DNSRequest, 1000)

	// Registrar el handler que reenvía al canal
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		requestChan <- DNSRequest{W: w, Req: req}
	})

	// Servidor UDP
	serverUDP := &dns.Server{
		Addr:    address,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}
	r.dnsServer = serverUDP

	go func() {
		if err := serverUDP.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start DNS UDP server: %v", err)
		}
	}()
	log.Printf("DNS UDP server started on %s", address)

	// Servidor TCP
	serverTCP := &dns.Server{
		Addr:    address,
		Net:     "tcp",
		Handler: dns.DefaultServeMux,
	}
	r.dnsServerTCP = serverTCP

	go func() {
		if err := serverTCP.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start DNS TCP server: %v", err)
		}
	}()
	log.Printf("DNS TCP server started on %s", address)

	log.Printf("DEBUG: Enabled ", r.enableDoT)
	log.Printf("DEBUG: cert ", r.dotCertFile)
	log.Printf("DEBUG: key ", r.dotKeyFile)

	// Servidor DoT si está habilitado
	if r.enableDoT && r.dotCertFile != "" && r.dotKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(r.dotCertFile, r.dotKeyFile)
		if err != nil {
			log.Printf("ERROR: failed to load TLS certificates: %v", err)
			return fmt.Errorf("failed to load TLS certificates: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		serverDoT := &dns.Server{
			Addr:      r.dotListenAddr,
			Net:       "tcp-tls",
			Handler:   dns.DefaultServeMux,
			TLSConfig: tlsConfig,
		}
		r.dnsServerDoT = serverDoT

		go func() {
			if err := serverDoT.ListenAndServe(); err != nil {
				log.Printf("ERROR: Failed to start DoT server: %v", err)
				log.Fatalf("Failed to start DoT server: %v", err)
			}
		}()
		log.Printf("DoT server started on %s", r.dotListenAddr)
	}

	log.Printf("All DNS servers started with %d worker threads", r.workerCount)

	var wg sync.WaitGroup
	wg.Add(r.workerCount)

	for i := 0; i < r.workerCount; i++ {
		go func(id int) {
			defer wg.Done()
			log.Printf("Starting DNS worker %d", id)

			for request := range requestChan {
				r.handleDNSRequest(request.W, request.Req)
			}
		}(i)
	}

	wg.Wait()
	return nil
}

// lookupCache busca si hay una entrada válida en caché
func (r *IPRedirector) lookupCache(key string) *dns.Msg {
	r.cache.mu.RLock()
	defer r.cache.mu.RUnlock()

	entry, found := r.cache.store[key]
	if !found {
		return nil
	}
	if time.Now().After(entry.expiration) {
		// Está expirada, la consideramos inválida (no la borramos aquí, se borrará en cleanExpiredEntries)
		return nil
	}
	return entry.msg
}

// saveCache guarda la respuesta DNS en caché, calculando la expiración a partir del TTL.
func (r *IPRedirector) saveCache(key string, resp *dns.Msg) {
	// Establecemos un TTL mínimo por defecto (ej: 3600s)
	var minTTL uint32 = 3600

	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if rr.Hdr.Ttl < minTTL {
				minTTL = rr.Hdr.Ttl
			}
		case *dns.AAAA:
			if rr.Hdr.Ttl < minTTL {
				minTTL = rr.Hdr.Ttl
			}
			// Añadir otros tipos de RR si quieres
		}
	}

	expiration := time.Now().Add(time.Duration(minTTL) * time.Second)

	r.cache.mu.Lock()
	r.cache.store[key] = &dnsCacheEntry{
		msg:        resp,
		expiration: expiration,
	}
	r.cache.mu.Unlock()
}

// startCacheCleaner lanza una goroutine que limpia las entradas expiradas cada cierto intervalo.
func (r *IPRedirector) startCacheCleaner(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				r.cleanExpiredEntries()
			case <-r.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// cleanExpiredEntries elimina del map las entradas cuyo TTL ya expiró
func (r *IPRedirector) cleanExpiredEntries() {
	now := time.Now()
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()

	for key, entry := range r.cache.store {
		if now.After(entry.expiration) {
			delete(r.cache.store, key)
		}
	}
}

// MAIN
func main() {
	ipBlocksFile := flag.String("ip-blocks", "ip_blocks.txt", "File containing IP blocks configuration")
	defaultTargetIP := flag.String("default-target-ip", "199.34.228.49", "Default IP to redirect to if no block matches")
	listenAddr := flag.String("listen", ":53", "Address to listen on (IP:port)")
	workerCount := flag.Int("workers", 4, "Number of worker threads")
	reloadInterval := flag.Duration("reload-interval", 30*time.Second, "Interval to check for file changes (e.g., 30s, 1m)")
	configFile := flag.String("config", "config.txt", "Configuration file path")
	
	// Nuevos flags para DoT
	enableDoT := flag.Bool("enable-dot", false, "Enable DNS over TLS (DoT)")
	dotListenAddr := flag.String("dot-listen", ":853", "DoT listen address (IP:port)")
	dotCertFile := flag.String("dot-cert", "", "Path to TLS certificate file for DoT")
	dotKeyFile := flag.String("dot-key", "", "Path to TLS private key file for DoT")
	upstreamDoT := flag.String("upstream-dot", "1.1.1.1:853", "Upstream DoT server (host:port)")
	
	flag.Parse()

	// Validar parámetros DoT si está habilitado
	if *enableDoT {
		if *dotCertFile == "" || *dotKeyFile == "" {
			log.Println("Warning: DoT is enabled but certificate files are not provided.")
			log.Println("To enable DoT server, please provide -dot-cert and -dot-key flags.")
			log.Println("DoT will only be used for upstream queries.")
		}
	}

	redirector, err := NewIPRedirector(
		*ipBlocksFile, 
		*configFile, 
		*defaultTargetIP, 
		*workerCount, 
		*reloadInterval,
		*enableDoT,
		*dotCertFile,
		*dotKeyFile,
		*dotListenAddr,
		*upstreamDoT,
	)
	if err != nil {
		log.Fatalf("Error initializing redirector: %v", err)
	}
	defer redirector.Stop()

	// Manejo de señales
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Iniciar servidor DNS
	go redirector.startDNSServer(*listenAddr)

	// Esperar señales
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			log.Println("Received SIGHUP, reloading configuration")
			redirector.TriggerReload()
		} else {
			log.Printf("Received signal %v, shutting down", sig)
			break
		}
	}
}

// Fin del código

