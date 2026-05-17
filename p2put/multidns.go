package p2put

import (
	"context"
	"strings"
	"time"
	"fmt"

	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/multiformats/go-multiaddr"

)

var extraStaticRelays []string

func init() {
	resolveAllDNSAddrsInit()
}
func resolveAllDNSAddrsInit() {
	fmt.Println("=== [init] DNSADDR 预解析 ===")
	ctx := context.Background()
	btime := time.Now()

	resolvedMap := resolveAllDNSAddrsQuiet(ctx, libp2pBootstrap)

	for _, addrs := range resolvedMap {
		for _, addr := range addrs {
			if strings.Contains(addr, ":") ||
				strings.Contains(addr, "/udp/") || strings.Contains(addr, "/wss/") {
				continue
			}
			if !containsAddr(extraStaticRelays, addr) {
				extraStaticRelays = append(extraStaticRelays, addr)
			}
		}
	}

	fmt.Printf("[*] 预解析完成，添加了 %d 个解析后的地址, %v\n", len(extraStaticRelays), time.Since(btime))
	fmt.Println()
}

func resolveAllDNSAddrsQuiet(ctx context.Context, addrStrs []string) map[string][]string {
	result := make(map[string][]string)

	for _, addrStr := range addrStrs {
		resolved, _ := resolveDNSAddrFully(ctx, addrStr)
		if len(resolved) > 0 {
			result[addrStr] = resolved
		}
	}

	return result
}

func containsAddr(slice []string, addr string) bool {
	for _, a := range slice {
		if a == addr {
			return true
		}
	}
	return false
}

var allStaticRelays = append(libp2pBootstrap, extraStaticRelays...)

func resolveDNSAddrFully(ctx context.Context, addrStr string) ([]string, []error) {
	var resolved []string
	var errs []error

	maddr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		errs = append(errs, fmt.Errorf("parse multiaddr: %w", err))
		return nil, errs
	}

	results, err := madns.Resolve(ctx, maddr)
	if err != nil {
		errs = append(errs, fmt.Errorf("dnsaddr resolve: %w", err))
	}

	for _, r := range results {
		rStr := r.String()

		if madns.Matches(r) {
			subResolved, subErrs := resolveDNSAddrFully(ctx, rStr)
			resolved = append(resolved, subResolved...)
			errs = append(errs, subErrs...)
			continue
		}

		if hasDNSComponent(r) {
			subResolved, subErrs := resolveDNSAddrFully(ctx, rStr)
			if len(subResolved) > 0 {
				resolved = append(resolved, subResolved...)
			} else {
				resolved = append(resolved, rStr)
			}
			errs = append(errs, subErrs...)
			continue
		}

		resolved = append(resolved, rStr)
	}

	return resolved, errs
}

func hasDNSComponent(maddr multiaddr.Multiaddr) bool {
	for _, proto := range maddr.Protocols() {
		if proto.Name == "dns4" || proto.Name == "dns6" || proto.Name == "dns" || proto.Name == "dnsaddr" {
			return true
		}
	}
	return false
}

func resolveAllDNSAddrs(ctx context.Context, addrStrs []string) map[string][]string {
	result := make(map[string][]string)

	for _, addrStr := range addrStrs {
		resolved, errs := resolveDNSAddrFully(ctx, addrStr)
		if len(resolved) > 0 {
			result[addrStr] = resolved
		}
		if len(errs) > 0 {
			fmt.Printf("  [!] 解析 %s 时发生错误:\n", addrStr)
			for _, err := range errs {
				fmt.Printf("      - %v\n", err)
			}
		}
	}

	return result
}

func printDNSResolutionResult(resolved map[string][]string) {
	fmt.Println()
	fmt.Println("=== DNSADDR 解析结果 ===")
	fmt.Println()

	for original, addrs := range resolved {
		fmt.Printf("📌 原始地址: %s\n", original)
		if len(addrs) == 0 {
			fmt.Println("   ❌ 解析失败，无结果")
		} else {
			fmt.Printf("   ✅ 解析到 %d 个地址:\n", len(addrs))
			for i, addr := range addrs {
				fmt.Printf("      [%02d] %s\n", i+1, addr)
			}
		}
		fmt.Println()
	}

	fmt.Println("=========================")
	fmt.Println()
}
