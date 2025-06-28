import time
import os
import psutil
import gc
import hashlib
import threading
from charm.toolbox.pairinggroup import PairingGroup, GT, G1, G2, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS

class PerformanceMonitor:
    def __init__(self):
        self.process = psutil.Process()
        # Initialize cpu_percent to start tracking
        self.process.cpu_percent()
        self.system_cpu_before = None
        self.system_cpu_after = None
    
    def get_memory_usage(self):
        """Get current memory usage in KB"""
        return self.process.memory_info().rss / 1024
    
    def start_monitoring(self):
        """Start comprehensive monitoring - call this before the operation"""
        # Reset process CPU monitoring
        self.process.cpu_percent()
        # Get baseline system CPU usage
        self.system_cpu_before = psutil.cpu_percent(interval=None)
        # Small delay to get accurate baseline
        time.sleep(0.01)
    
    def get_cpu_percent_isolated(self):
        """Get CPU usage percentage for this process during the operation"""
        # Get process CPU usage
        process_cpu = self.process.cpu_percent()
        
        # Get system CPU usage after operation
        self.system_cpu_after = psutil.cpu_percent(interval=None)
        
        # If process CPU is available, use it directly
        if process_cpu > 0:
            return process_cpu
        
        # Fallback: estimate based on system CPU change
        if self.system_cpu_before is not None and self.system_cpu_after is not None:
            cpu_delta = max(0, self.system_cpu_after - self.system_cpu_before)
            return min(cpu_delta, 100.0)  # Cap at 100%
        
        return 0.0

class HybridABENCBenchmark:
    def __init__(self):
        self.group = PairingGroup('SS512')
        self.dacmacs = DACMACS(self.group)
        self.monitor = PerformanceMonitor()
        
        # Setup DACMACS
        self.GPP, self.GMK = self.dacmacs.setup()
        
        # Setup authorities and users
        self.users = {}
        self.authorities = {}
        
        # Create authority with attributes
        self.authority_id = "authority1"
        self.authority_attributes = ["MEDICAL", "RESEARCH", "ADMIN", "PUBLIC", "CONFIDENTIAL"]
        self.dacmacs.setupAuthority(self.GPP, self.authority_id, self.authority_attributes, self.authorities)
        
        # Create test user (Alice)
        self.alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}
        self.alice['keys'], self.users[self.alice['id']] = self.dacmacs.registerUser(self.GPP)
        
        # Generate keys for Alice for all attributes except one (to test policy satisfaction)
        for attr in self.authority_attributes[:-1]:  # All except last attribute
            self.dacmacs.keygen(self.GPP, self.authorities[self.authority_id], attr, 
                              self.users[self.alice['id']], self.alice['authoritySecretKeys'])
        
        # Test policy string
        self.policy_str = '((MEDICAL or RESEARCH) and (ADMIN or PUBLIC))'
        
    def generate_test_data(self, size_kb):
        """Generate test data of specified size in KB"""
        return os.urandom(size_kb * 1024)
    
    def derive_symmetric_key(self, seed):
        """Derive a symmetric key from seed using a more robust method"""
        try:
            # Method 1: Use pairing and hash the result
            g1_seed = self.group.hash(seed, G1)
            g2_seed = self.group.hash(seed, G2)
            pairing_result = pair(g1_seed, g2_seed)
            
            # Convert pairing result to bytes more safely
            try:
                pairing_bytes = objectToBytes(pairing_result, self.group)
                # Use SHA-256 to derive a fixed-length key
                key_hash = hashlib.sha256(pairing_bytes).digest()
                return key_hash
            except Exception as serialize_error:
                # If serialization fails, use string representation
                pairing_str = str(pairing_result).encode('utf-8')
                key_hash = hashlib.sha256(pairing_str + seed).digest()
                return key_hash
            
        except Exception as e:
            # Fallback: Use direct hash of seed with additional entropy
            fallback_data = seed + b"fallback_salt_12345"
            return hashlib.sha256(fallback_data).digest()
    
    def encrypt_hybrid(self, message):
        """Perform hybrid encryption and measure performance"""
        try:
            # Force garbage collection before measurement
            gc.collect()
            
            # Get initial metrics and start monitoring
            start_memory = self.monitor.get_memory_usage()
            self.monitor.start_monitoring()
            start_time = time.perf_counter()
            
            # Step 1: Generate seed and derive symmetric key
            seed = os.urandom(32)  # Increase seed size for better security
            sym_key_bytes = self.derive_symmetric_key(seed)
            
            # Validate key length
            if len(sym_key_bytes) != 32:
                raise ValueError(f"Invalid key length: {len(sym_key_bytes)}")
            
            # Step 2: Generate a random key for ABENC encryption
            k = self.group.random(GT)
            
            # Step 3: Encrypt the random key using ABENC with policy
            ciphertext_abenc = self.dacmacs.encrypt(self.GPP, self.policy_str, k, self.authorities[self.authority_id])
            
            # Step 4: Use the random key to encrypt the symmetric key seed
            # Convert GT element to bytes for XOR operation
            try:
                k_bytes = objectToBytes(k, self.group)
                # Ensure we have exactly 32 bytes for the seed encryption
                k_hash = hashlib.sha256(k_bytes).digest()
                encrypted_seed = bytes(a ^ b for a, b in zip(seed, k_hash))
            except Exception as e:
                # Fallback method
                k_str = str(k).encode('utf-8')
                k_hash = hashlib.sha256(k_str).digest()
                encrypted_seed = bytes(a ^ b for a, b in zip(seed, k_hash))
            
            # Step 5: Encrypt message with symmetric key
            sym_cipher = SymmetricCryptoAbstraction(sym_key_bytes)
            ciphertext_sym = sym_cipher.encrypt(message)
            
            # Get final metrics
            end_time = time.perf_counter()
            cpu_percent = self.monitor.get_cpu_percent_isolated()
            end_memory = self.monitor.get_memory_usage()
            
            encryption_time = end_time - start_time
            memory_used = end_memory - start_memory
            
            return {
                'ciphertext_abenc': ciphertext_abenc,
                'encrypted_seed': encrypted_seed,
                'ciphertext_sym': ciphertext_sym,
                'time': encryption_time,
                'cpu_percent': cpu_percent,
                'memory_kb': memory_used
            }
        except Exception as e:
            print(f"Encryption error: {e}")
            raise
    
    def decrypt_hybrid(self, ciphertext_abenc, encrypted_seed, ciphertext_sym, max_retries=2):
        """Perform hybrid decryption and measure performance"""
        retry_count = 0
        last_error = None
        
        while retry_count <= max_retries:
            try:
                # Force garbage collection before measurement
                gc.collect()
                
                # Get initial metrics and start monitoring
                start_memory = self.monitor.get_memory_usage()
                self.monitor.start_monitoring()
                start_time = time.perf_counter()
                
                # Step 1: Generate token using ABENC
                TK = self.dacmacs.generateTK(self.GPP, ciphertext_abenc, 
                                           self.alice['authoritySecretKeys'], 
                                           self.alice['keys'][0])
                
                if TK == False:
                    raise ValueError("Failed to generate token - policy not satisfied")
                
                # Step 2: Decrypt to get the random key
                k_decrypted = self.dacmacs.decrypt(ciphertext_abenc, TK, self.alice['keys'][1])
                
                if k_decrypted is None:
                    if retry_count < max_retries:
                        retry_count += 1
                        print(f"    ABENC decryption returned None, retrying ({retry_count}/{max_retries})...")
                        continue
                    else:
                        raise ValueError("ABENC decryption failed after all retries - returned None")
                
                # Step 3: Use the decrypted key to decrypt the seed
                try:
                    k_bytes = objectToBytes(k_decrypted, self.group)
                    k_hash = hashlib.sha256(k_bytes).digest()
                    decrypted_seed = bytes(a ^ b for a, b in zip(encrypted_seed, k_hash))
                except Exception as e:
                    # Fallback method
                    k_str = str(k_decrypted).encode('utf-8')
                    k_hash = hashlib.sha256(k_str).digest()
                    decrypted_seed = bytes(a ^ b for a, b in zip(encrypted_seed, k_hash))
                
                # Validate seed
                if len(decrypted_seed) != 32:
                    raise ValueError(f"Invalid decrypted seed length: {len(decrypted_seed)}")
                
                # Step 4: Reconstruct symmetric key
                decrypted_key_bytes = self.derive_symmetric_key(decrypted_seed)
                
                # Validate key
                if len(decrypted_key_bytes) != 32:
                    raise ValueError(f"Invalid decrypted key length: {len(decrypted_key_bytes)}")
                
                # Step 5: Decrypt message
                sym_cipher_recv = SymmetricCryptoAbstraction(decrypted_key_bytes)
                plaintext = sym_cipher_recv.decrypt(ciphertext_sym)
                
                # Get final metrics
                end_time = time.perf_counter()
                cpu_percent = self.monitor.get_cpu_percent_isolated()
                end_memory = self.monitor.get_memory_usage()
                
                decryption_time = end_time - start_time
                memory_used = end_memory - start_memory
                
                return {
                    'plaintext': plaintext,
                    'time': decryption_time,
                    'cpu_percent': cpu_percent,
                    'memory_kb': memory_used,
                    'retries': retry_count
                }
                
            except Exception as e:
                last_error = e
                if retry_count < max_retries:
                    retry_count += 1
                    print(f"    Decryption error, retrying ({retry_count}/{max_retries}): {e}")
                    continue
                else:
                    print(f"Decryption error after all retries: {e}")
                    raise
        
        # Should not reach here
        raise last_error if last_error else Exception("Unknown decryption error")
    
    def run_benchmark(self, data_sizes_kb, iterations=3):
        """Run benchmark for different data sizes"""
        results = []
        
        for size_kb in data_sizes_kb:
            print(f"\nTesting {size_kb}KB data...")
            
            try:
                # Generate test data
                test_data = self.generate_test_data(size_kb)
                
                # Run multiple iterations and average the results
                enc_times, dec_times = [], []
                enc_cpu, dec_cpu = [], []
                enc_memory, dec_memory = [], []
                total_retries = 0
                
                for i in range(iterations):
                    print(f"  Iteration {i+1}/{iterations}")
                    
                    try:
                        # Encryption benchmark
                        enc_result = self.encrypt_hybrid(test_data)
                        
                        # Decryption benchmark
                        dec_result = self.decrypt_hybrid(
                            enc_result['ciphertext_abenc'], 
                            enc_result['encrypted_seed'],
                            enc_result['ciphertext_sym']
                        )
                        
                        # Verify correctness
                        if dec_result['plaintext'] != test_data:
                            print(f"  ERROR: Decryption failed for {size_kb}KB!")
                            continue
                        
                        # Record successful results
                        enc_times.append(enc_result['time'])
                        enc_cpu.append(enc_result['cpu_percent'])
                        enc_memory.append(enc_result['memory_kb'])
                        
                        dec_times.append(dec_result['time'])
                        dec_cpu.append(dec_result['cpu_percent'])
                        dec_memory.append(dec_result['memory_kb'])
                        
                        total_retries += dec_result.get('retries', 0)
                        
                    except Exception as e:
                        print(f"  ERROR in iteration {i+1}: {e}")
                        continue
                
                if not enc_times:  # No successful iterations
                    print(f"  SKIPPING {size_kb}KB due to errors")
                    continue
                
                # Calculate averages
                avg_enc_time = sum(enc_times) / len(enc_times)
                avg_dec_time = sum(dec_times) / len(dec_times)
                avg_enc_cpu = sum(enc_cpu) / len(enc_cpu)
                avg_dec_cpu = sum(dec_cpu) / len(dec_cpu)
                avg_enc_memory = sum(enc_memory) / len(enc_memory)
                avg_dec_memory = sum(dec_memory) / len(dec_memory)
                
                results.append({
                    'size_kb': size_kb,
                    'successful_iterations': len(enc_times),
                    'total_retries': total_retries,
                    'encryption': {
                        'time_ms': avg_enc_time * 1000,
                        'cpu_percent': avg_enc_cpu,
                        'memory_kb': avg_enc_memory
                    },
                    'decryption': {
                        'time_ms': avg_dec_time * 1000,
                        'cpu_percent': avg_dec_cpu,
                        'memory_kb': avg_dec_memory
                    }
                })
                
            except Exception as e:
                print(f"  ERROR testing {size_kb}KB: {e}")
                continue
        
        return results
    
    def print_results(self, results):
        """Print benchmark results in a formatted table"""
        print("\n" + "="*120)
        print("HYBRID ABENC (DACMACS) ENCRYPTION/DECRYPTION BENCHMARK RESULTS")
        print("="*120)
        print(f"Policy: {self.policy_str}")
        print(f"User attributes: {list(self.alice['authoritySecretKeys']['AK'].keys())}")
        print("="*120)
        
        header = f"{'Size':<8} | {'Success':<7} | {'Retries':<7} | {'Encryption':<35} | {'Decryption':<35}"
        print(header)
        print("-" * len(header))
        print(f"{'(KB)':<8} | {'Rate':<7} | {'Total':<7} | {'Time(ms)':<10} {'CPU(%)':<10} {'RAM(KB)':<10} | {'Time(ms)':<10} {'CPU(%)':<10} {'RAM(KB)':<10}")
        print("-" * len(header))
        
        for result in results:
            size = result['size_kb']
            success_rate = f"{result['successful_iterations']}/3"
            retries = result.get('total_retries', 0)
            enc = result['encryption']
            dec = result['decryption']
            
            print(f"{size:<8} | "
                  f"{success_rate:<7} | "
                  f"{retries:<7} | "
                  f"{enc['time_ms']:<10.2f} {enc['cpu_percent']:<10.1f} {enc['memory_kb']:<10.1f} | "
                  f"{dec['time_ms']:<10.2f} {dec['cpu_percent']:<10.1f} {dec['memory_kb']:<10.1f}")
        
        print("="*120)
        
        # Print summary statistics
        total_tests = sum(result['successful_iterations'] for result in results)
        total_retries = sum(result.get('total_retries', 0) for result in results)
        if total_tests > 0:
            retry_rate = (total_retries / total_tests) * 100
            print(f"\nSummary: {total_tests} successful tests, {total_retries} retries ({retry_rate:.1f}% retry rate)")

def main():
    """Main benchmark execution"""
    print("Starting Hybrid ABENC (DACMACS) Encryption Benchmark...")
    print("Note: For accurate CPU measurements, please minimize other running applications.")
    
    # Test data sizes in KB
    data_sizes = [1, 10, 100, 250, 500, 750, 1024, 5120, 7168, 10240]  # 1KB to 10MB
    
    # Initialize benchmark
    benchmark = HybridABENCBenchmark()
    
    # Run benchmarks
    results = benchmark.run_benchmark(data_sizes, iterations=3)
    
    # Print results
    benchmark.print_results(results)
    
    # Save results to file
    import json
    with open('/Users/thanhtuan/son/charm/benchmark_abenc_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: /Users/thanhtuan/son/charm/benchmark_abenc_results.json")

if __name__ == "__main__":
    main()
