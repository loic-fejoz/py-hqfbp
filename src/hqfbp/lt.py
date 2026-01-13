import struct
import math
from typing import List, Tuple, Generator, Optional, Dict, Set

# --- Shared Deterministic PRNG ---

class SplitMix64:
    """
    SplitMix64 PRNG.
    Ported to ensure 100% identical output between Python and Rust.
    Output: 64-bit unsigned integers.
    """
    def __init__(self, seed: int):
        # Ensure 64-bit truncation using mask
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.state
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z &= 0xFFFFFFFFFFFFFFFF
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        z &= 0xFFFFFFFFFFFFFFFF
        z = z ^ (z >> 31)
        return z

# --- Robust Soliton Distribution ---

class RobustSoliton:
    """
    Generates degree distribution for LT Codes.
    """
    def __init__(self, k: int, c: float = 0.1, delta: float = 0.5):
        self.k = k
        self.cdf = self._gen_cdf(k, c, delta)

    def _gen_cdf(self, k: int, c: float, delta: float) -> List[float]:
        # Ideal Soliton Distribution
        rho = [0.0] * (k + 1)
        rho[1] = 1.0 / k
        for d in range(2, k + 1):
            rho[d] = 1.0 / (d * (d - 1))

        # Robust Component
        tau = [0.0] * (k + 1)
        s = c * math.log(k / delta) * math.sqrt(k)
        for d in range(1, k + 1):
            if d < round(k / s) - 1:
                tau[d] = s / k * (1 / d)
            elif d == round(k / s):
                tau[d] = s * math.log(s / delta) / k
            else:
                tau[d] = 0.0 # Upper part usually 0 until K/S? Simplified here.

        # Normalize Z
        z = sum(rho) + sum(tau)
        
        # Calculate CDF
        mu = [(rho[d] + tau[d]) / z for d in range(k + 1)]
        cdf = [0.0] * (k + 2)
        current = 0.0
        for d in range(1, k + 1):
            current += mu[d]
            cdf[d] = current
        cdf[k+1] = 1.0
        return cdf

    def sample(self, prng: SplitMix64) -> int:
        """Sample a degree using the PRNG."""
        # Convert u64 to float [0, 1)
        val = prng.next_u64() / (2**64)
        
        # Linear scan for CDF (K is usually small enough, else binary search)
        for d in range(1, self.k + 1):
            if val < self.cdf[d]:
                return d
        return 1 # Fallback

# --- LT Code Logic ---

def xor_block(dest: bytearray, src: bytes):
    """XOR src into dest in-place using 64-bit words where possible."""
    # Python ints range arbitrary, but `int.from_bytes` is fast.
    # For simplicity and clarity in "easy to implement" context: simple loop.
    # Optimization: use xor_bytes helper via int conversion if needed, but byte-loop is O(N).
    for i in range(len(dest)):
        dest[i] ^= src[i]

class LTEncoder:
    def __init__(self, data: bytes, symbol_size: int):
        self.symbol_size = symbol_size
        self.original_len = len(data)
        
        # Pad data to multiple of symbol_size
        if len(data) % symbol_size != 0:
            data += b'\x00' * (symbol_size - (len(data) % symbol_size))
            
        self.blocks = [data[i : i + symbol_size] for i in range(0, len(data), symbol_size)]
        self.k = len(self.blocks)
        self.dist = RobustSoliton(self.k)

    def encode(self, repair_count: int) -> Generator[bytes, None, None]:
        # Step 1: Emit all K source blocks systematically (Degree 1)
        # This is a deviation from pure LT but standard for usability (systematic code).
        # We manually force ESI 0..K-1 to be "Source Block i".
        # This requires the decoder to know this convention OR we treat them as normal drops
        # but forced.
        #
        # Better approach:
        # Just generate drops indefinitely based on ESI. If user wants systematic,
        # we can't easily force it with purely random LT unless we hardcode "ESI < K are identity".
        # Let's do the "ESI < K are identity" systematic approach.
        
        count = self.k + repair_count
        
        for esi in range(count):
            if esi < self.k:
                # Systematic part
                # Drop format: [ESI (4 bytes)] [Payload]
                header = struct.pack(">I", esi)
                yield header + self.blocks[esi]
            else:
                # Encoded (Repair) part
                prng = SplitMix64(esi)
                degree = self.dist.sample(prng)
                
                # Sample neighbors
                # We need 'degree' unique indices from 0..K-1.
                # Use PRNG to shuffle or pick. Rejection sampling is easiest for small degree.
                neighbors = set()
                while len(neighbors) < degree:
                    # Next u64 modulo K. Note: Bias exists if K not power of 2, 
                    # but negligible for 64-bit space.
                    idx = prng.next_u64() % self.k
                    neighbors.add(idx)
                
                # XOR neighbors
                block = bytearray(self.symbol_size)
                # First one copy directly
                first = True
                for idx in neighbors:
                    if first:
                        block[:] = self.blocks[idx]
                        first = False
                    else:
                        xor_block(block, self.blocks[idx])
                
                header = struct.pack(">I", esi)
                yield header + block

class LTDecoder:
    def __init__(self, total_len: int, symbol_size: int):
        self.total_len = total_len
        self.symbol_size = symbol_size
        self.k = math.ceil(total_len / symbol_size)
        self.dist = RobustSoliton(self.k)
        
        # State
        self.blocks: Dict[int, bytes] = {} # Recovered source blocks
        self.graph: Dict[int, Tuple[Set[int], bytearray]] = {} # ESI -> (Neighbors, Payload)
        
        # Edges needed for peeling (Block ID -> Set of Drop ESIs that need this block)
        self.block_dependencies: Dict[int, Set[int]] = {i: set() for i in range(self.k)}

    def decode(self, packet: bytes) -> bool:
        if len(packet) < 4 + self.symbol_size:
            return False
            
        esi = struct.unpack(">I", packet[:4])[0]
        payload = bytearray(packet[4:])
        
        if len(payload) != self.symbol_size:
            # Should truncated payload be allowed if it's the last block?
            # For simplicity, demand padding.
            return False

        if esi < self.k:
            # Systematic packet: We learned a source block directly!
            if esi not in self.blocks:
                self.blocks[esi] = bytes(payload)
                self._propagate(esi)
        else:
            # Encoded packet
            prng = SplitMix64(esi)
            degree = self.dist.sample(prng)
            neighbors = set()
            while len(neighbors) < degree:
                idx = prng.next_u64() % self.k
                neighbors.add(idx)
            
            # Immediately XOR out any blocks we already know
            unknown_neighbors = set()
            for idx in neighbors:
                if idx in self.blocks:
                    xor_block(payload, self.blocks[idx])
                else:
                    unknown_neighbors.add(idx)
            
            if not unknown_neighbors:
                # Redundant packet (all neighbors known)
                pass 
            elif len(unknown_neighbors) == 1:
                # We solved a block!
                new_idx = unknown_neighbors.pop()
                if new_idx not in self.blocks:
                    self.blocks[new_idx] = bytes(payload)
                    self._propagate(new_idx)
            else:
                # Store for later
                # We key by ESI.
                self.graph[esi] = (unknown_neighbors, payload)
                for idx in unknown_neighbors:
                    self.block_dependencies[idx].add(esi)
                    
        return len(self.blocks) == self.k

    def _propagate(self, resolved_idx: int):
        """Peel the resolved block from all waiting drops."""
        block_val = self.blocks[resolved_idx]
        
        # Get list of drops waiting for this block
        waiting_drops = self.block_dependencies[resolved_idx]
        
        # We must copy the set because we might modify it while iterating (if we solve more)
        # Actually, we remove from self.block_dependencies as we process?
        # A drop might be waiting for multiple blocks.
        
        # Iterate over a copy of the drops that depend on this block
        chunks_to_check = list(waiting_drops)
        
        for esi in chunks_to_check:
            if esi not in self.graph:
                continue
                
            neighbors, payload = self.graph[esi]
            
            if resolved_idx in neighbors:
                xor_block(payload, block_val)
                neighbors.remove(resolved_idx)
                
                # Check if this drop is now solvable
                if len(neighbors) == 1:
                    new_idx = neighbors.pop()
                    # Remove this drop from graph, it's consumed (became a source block)
                    del self.graph[esi]
                    
                    if new_idx not in self.blocks:
                        self.blocks[new_idx] = bytes(payload)
                        # Recurse
                        self._propagate(new_idx)
                elif len(neighbors) == 0:
                     # Redundant
                     del self.graph[esi]

    def get_result(self) -> Optional[bytes]:
        if len(self.blocks) < self.k:
            return None
        
        res = bytearray()
        for i in range(self.k):
            res.extend(self.blocks[i])
            
        return bytes(res[:self.total_len])
