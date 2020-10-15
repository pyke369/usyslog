package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	progname   = "usyslog"
	version    = "1.0.0"
	priorities = map[string]syslog.Priority{
		"emerg":   syslog.LOG_EMERG,
		"alert":   syslog.LOG_ALERT,
		"crit":    syslog.LOG_CRIT,
		"err":     syslog.LOG_ERR,
		"warning": syslog.LOG_WARNING,
		"notice":  syslog.LOG_NOTICE,
		"info":    syslog.LOG_INFO,
		"debug":   syslog.LOG_DEBUG,
	}
	facilities = map[string]syslog.Priority{
		"kern":     syslog.LOG_KERN,
		"user":     syslog.LOG_USER,
		"mail":     syslog.LOG_MAIL,
		"daemon":   syslog.LOG_DAEMON,
		"auth":     syslog.LOG_AUTH,
		"syslog":   syslog.LOG_SYSLOG,
		"lpr":      syslog.LOG_LPR,
		"news":     syslog.LOG_NEWS,
		"uucp":     syslog.LOG_UUCP,
		"cron":     syslog.LOG_CRON,
		"authpriv": syslog.LOG_AUTHPRIV,
		"ftp":      syslog.LOG_FTP,
		"local0":   syslog.LOG_LOCAL0,
		"local1":   syslog.LOG_LOCAL1,
		"local2":   syslog.LOG_LOCAL2,
		"local3":   syslog.LOG_LOCAL3,
		"local4":   syslog.LOG_LOCAL4,
		"local5":   syslog.LOG_LOCAL5,
		"local6":   syslog.LOG_LOCAL6,
		"local7":   syslog.LOG_LOCAL7,
	}
)

// parse argument main value and options
func parse(input string) (value string, options map[string]string) {
	parts := strings.SplitN(input, "?", 2)
	value, options = parts[0], map[string]string{}
	if len(parts) > 1 {
		for _, option := range strings.Split(parts[1], ",") {
			if parts := strings.SplitN(option, "=", 2); len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
				options[strings.ToLower(parts[0])] = parts[1]
			}
		}
	}
	return
}

// get local fully-qualified domain name
func fqdn() string {
	value, _ := os.Hostname()
	value = strings.TrimSuffix(value, ".")
	if value != "" && strings.Count(value, ".") == 0 {
		if addresses, err := net.LookupHost(value); err == nil {
			for _, address := range addresses {
				if hostnames, err := net.LookupAddr(address); err == nil && len(hostnames) > 0 {
					for _, hostname := range hostnames {
						if strings.Count(hostname, ".") > 1 {
							value = strings.TrimSuffix(hostname, ".")
							break
						}
					}
				}
			}
		}
	}
	return value
}

// main program entry
func main() {
	// check command-line arguments
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: usyslog <source-path[?<options>]> <destination-url[?<options>]>\n")
		os.Exit(1)
	}
	log.Printf("%s v%s started\n", progname, version)

	// manage remote connection and forward queued messages
	queue := make(chan string, 8192)
	go func() {
		var output net.Conn

		matcher, last, timer, probe := regexp.MustCompile(`^(udp|tcp|tls)://(.+)$`), time.Now(), time.NewTicker(time.Second), make([]byte, 1)
		destination, options := parse(os.Args[2])
		for {
			select {
			case line := <-queue:
				if output != nil {
					output.SetWriteDeadline(time.Now().Add(time.Second))
					if _, err := output.Write([]byte(line)); err != nil {
						output.Close()
						output = nil
						log.Printf("destination %s closed (%v)\n", destination, err)
					}
				}
			case <-timer.C:
			}
			if output == nil && time.Now().Sub(last) >= 3*time.Second {
				last = time.Now()
				if parts := matcher.FindStringSubmatch(destination); parts != nil {
					if _, _, err := net.SplitHostPort(parts[2]); err != nil {
						switch parts[1] {
						case "udp", "tcp":
							parts[2] += ":514"
						case "tls":
							parts[2] += ":6514"
						}
					}
					switch parts[1] {
					case "udp", "tcp":
						if handle, err := net.DialTimeout(parts[1], parts[2], 3*time.Second); err == nil {
							output = handle
						} else {
							log.Printf("cannot connect destination %s (%v)\n", destination, err)
						}
					case "tls":
						config := tls.Config{}
						if options["insecure"] == "true" {
							config.InsecureSkipVerify = true
						}
						if options["cert"] != "" && options["key"] != "" {
							if certificate, err := tls.LoadX509KeyPair(options["cert"], options["key"]); err == nil {
								config.Certificates = []tls.Certificate{certificate}
							}
						}
						if handle, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", parts[2], &config); err == nil {
							if options["trusted"] != "" {
								matcher, _ := regexp.Compile(options["trusted"])
								subject := ""
								if len(handle.ConnectionState().PeerCertificates) > 0 {
									subject = handle.ConnectionState().PeerCertificates[0].Subject.String()
								}
								if matcher == nil || subject == "" || !matcher.MatchString(subject) {
									log.Printf("cannot connect destination %s (untrusted DN %s)\n", destination, subject)
									handle.Close()
								} else {
									output = net.Conn(handle)
								}
							} else {
								output = net.Conn(handle)
							}
						} else {
							log.Printf("cannot connect destination %s (%v)\n", destination, err)
						}
					}
					if output != nil {
						output.SetReadDeadline(time.Now().Add(time.Second))
						if _, err := output.Read(probe); err != nil && !os.IsTimeout(err) {
							output.Close()
							output = nil
							log.Printf("cannot connect destination %s (%v)\n", destination, err)
						} else {
							log.Printf("destination %s connected\n", destination)
						}
					}
				}
			}
		}
	}()

	// manage source named pipe and queue received events
	var input *os.File

	rfc3164 := regexp.MustCompile(`^(?P<hdr><\d{1,3}>[a-zA-Z]{3} \d{1,2} \d{2}:\d{2}:\d{2} )(?P<host>\S+ )?(?P<msg>[^\[:]+(?:\[\d+\])?: .+)$`)
	rfc5424 := regexp.MustCompile(`^(?P<hdr><\d{1,3}>\d )(?P<date>\S+ )(?P<host>\S+ )(?P<tag>\S+ )(?P<pid>(?:\d+|-) )(?P<msgid>\S+ )(?P<sdata>(?:-|(?:\[[^\]+]\])+) )(?P<msg>.+)$`)
	host := fqdn()
	source, options := parse(os.Args[1])
	for {
		if input == nil {
			os.MkdirAll(filepath.Dir(source), 0755)
			if info, err := os.Stat(source); err == nil {
				if info.Mode()&os.ModeType != os.ModeNamedPipe {
					os.Remove(source)
				}
			}
			mode := uint32(0666)
			if value, _ := strconv.ParseInt(options["mode"], 8, 0); value != 0 {
				mode = uint32(value)
			}
			syscall.Mkfifo(source, mode)
			input, _ = os.Open(source)
		}
		if input != nil {
			reader := bufio.NewReader(input)
			for {
				if line, err := reader.ReadString('\n'); err != nil {
					break
				} else {
					line = strings.TrimSpace(line)
					if parts := rfc3164.FindStringSubmatch(line); parts != nil {
						if parts[rfc3164.SubexpIndex("host")] == "" {
							parts[rfc3164.SubexpIndex("host")] = strings.Split(host, ".")[0] + " "
						}
						line = fmt.Sprintf("%s%s%s",
							parts[rfc3164.SubexpIndex("hdr")], parts[rfc3164.SubexpIndex("host")],
							parts[rfc3164.SubexpIndex("msg")])
					} else if parts := rfc5424.FindStringSubmatch(line); parts != nil {
						if parts[rfc5424.SubexpIndex("date")] == "- " {
							parts[rfc5424.SubexpIndex("date")] = time.Now().Format(time.RFC3339)
						}
						if parts[rfc5424.SubexpIndex("host")] == "- " {
							parts[rfc5424.SubexpIndex("host")] = host + " "
						}
						if parts[rfc5424.SubexpIndex("tag")] == "- " {
							parts[rfc5424.SubexpIndex("tag")] = progname + " "
							parts[rfc5424.SubexpIndex("pid")] = fmt.Sprintf("%d ", os.Getpid())
						}
						line = fmt.Sprintf("%s%s%s%s%s%s%s%s",
							parts[rfc5424.SubexpIndex("hdr")], parts[rfc5424.SubexpIndex("date")],
							parts[rfc5424.SubexpIndex("host")], parts[rfc5424.SubexpIndex("tag")],
							parts[rfc5424.SubexpIndex("pid")], parts[rfc5424.SubexpIndex("msgid")],
							parts[rfc5424.SubexpIndex("sdata")], parts[rfc5424.SubexpIndex("msg")])
					} else {
						priority, facility, tag := priorities["info"], facilities["syslog"], progname
						if priorities[options["priority"]] != 0 {
							priority = priorities[options["priority"]]
						}
						if facilities[options["facility"]] != 0 {
							facility = facilities[options["facility"]]
						}
						if options["tag"] != "" {
							tag = options["tag"]
						}
						line = fmt.Sprintf("<%d>%s %s %s[%d]: %s",
							priority|facility, time.Now().Format(time.Stamp),
							strings.Split(host, ".")[0], tag, os.Getpid(), line)
					}
					queue <- line + "\n"
				}
			}
		}
		input.Close()
		input = nil
		time.Sleep(time.Second)
	}
}
