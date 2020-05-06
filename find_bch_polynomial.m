## Brute force a BCH polynomial knowing syndrome outputs
##
## The goal of this script is to find a way to determine the primary BCH
## polynomial that is used by a given hardware ECC engine to derive its
## generator polynomial for a given BCH code.
##
## Depending of the Gallois Field order of the desired BCH code, there are a
## defined number of primary polynomial that can be used. Polynomials can be
## under the form of an integer or given as a binary array. In both cases, set
## bits represent the coefficients for a given order of magnitude of a
## polynomial representation of the code:
##     0xD = b1101 = 1 + x^2 + x^3
## There are tables which list, for a given order, how to derive the
## primary polynomials, see:
##     https://www.partow.net/programming/polynomials/index.html
## Given an initial state using:
##     {data to protect: 4096 bits, strength: t = 4 bits}
## we can derive a Gallois field order m that is bigger than the amount of data
## to protect so that:
##     2^m > 4096 => m = 13
## The total amount of manipulated data (payload, parity bits, eventual
## padding), also called BCH codeword in papers, is:
##     n = 2^m-1 = 8191
## We expect that ECC bytes will be written into 7 bytes (derivation
## available in Linux lib/bch.c). The exact number of parity bits is:
##     m * t = 13 * 4 = 52 bits (6,5 bytes)
## Given the size of the codeword, it is then possible to derive the
## number of parity bits which are needed to achieve a certain strength,
## and this gives us the maximum message length:
##     k = 8191 - 52 = 8139
## With BCH, it has been shown that if (n, k) is a valid BCH code, then
## (n - x, k - x) will also be valid. In our situation, it means that:
##     x = k - 4096 = 8139 - 4096 = 4043
## Then, we must feed our algorithm with known inputs and output. We write an
## ECC step full of 0s and another one full of Fs. With this we are able to
## find the output of the BCH encoding, giving a syndrome of 52 bits in both
## cases. We can now, for each primary polynom, produce a generator polynom,
## use it to encode both buffers and compare the output syndromes with the
## expected buffers (from the hardware output).
## If running this test do not give any match, try swapping bits at byte
## level and eventually reorder bytes as well.

pkg load signal
pkg load communications
clear

# Inputs
target_code00s = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
target_codeFFs = [1,1,0,0,0,0,1,1,0,0,1,1,0,1,1,1,1,1,0,1,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,0,0,1,0,0,1,0,0,0,0,0,0,1,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,1,1,0,1,0,1,0,1,0,0,0,0,0,1,0,1,1,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,1,0,0,0,1,1,0,1,1,0,1,1,0,0,1,0,0,0,0,1,0,0,1,0,1,0,1,0,0,1,1,1,1,0,0,1,0,0,0,1,1,0,0,1,0,0,1,0,0,0,1,0,1,1,1,1,0,0,0,0,0,0,0,1,1,0,1,1,0,1,0,0,1,1,0,1,1,0,1,1,1,1,0,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,0,1,1,1,0,1,0,1,1,1,0,0,0,0,0,1,0,1,1,1,1,0,0,0,0,0,1,0,0,0,1,0,1,0,0,0,1,1,0,1,0,0,0,1,1,0,0,1,0,1,1,0,1,1,1,0,0,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,1,0,1,1,0,0,1,1,0,0,1,1,0,0,0,1,1,1,0,1,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,1,0,1,0,0,0,0,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,0];
eccsize = 1024
eccstrength = 24

# Useful definitions
min_m = 5;
eccsizeb = eccsize * 8;
buf_00s(1:eccsizeb) = 0;
buf_FFs(1:eccsizeb) = 1;

function bit = fls (val)
  for i = 1:32
    if (bitget(val, i))
      bit = i;
    endif
  endfor
  bit = bit - 1;
endfunction

function k = find_k (n, t)
  npoly = bchpoly(n); # This takes a long time
  for i = 1:rows(npoly)
    if (npoly(i,3) == t)
      k = npoly(i,2); # Just set k and skip this function when you know it
      break;
    endif
  endfor
endfunction

# Sanity checks
m = fls(8 * eccsize) + 1
if (m < min_m)
  printf("m = %d should be in the [5,+oo[ range\n", m);
endif

eccbytes = ceil(eccstrength * m / 8);
t = floor((eccbytes * 8) / m);
if (t != eccstrength)
  printf("mismatch between desired strength %d and derived %d\n", eccstrength, t);
endif

# Local variables
n = bitset(0, m + 1) - 1 # codeword len (bits) (including parity bits)
p = m * t # parity bits
k = find_k(n, t)
x = k - eccsizeb

# Brute-force
evalc('prim_poly = primpoly(m, "all")'); # Trick: use evalc to prevent printf/disp()
for i = 1:columns(prim_poly)
  printf("Trying primary polynomial #%d: 0x%x\n", i, prim_poly(i));
  gen_poly = bchpoly(n, k, prim_poly(i));
  codeFF = bchenco(buf_FFs, n - x, k - x, gen_poly, "end");
  code00 = bchenco(buf_00s, n - x, k - x, gen_poly, "end");
  if ((codeFF(eccsizeb + 1:eccsizeb + p) == target_codeFFs) &&
      (code00(eccsizeb + 1:eccsizeb + p) == target_code00s))
      printf("Primary polynomial found! 0x%x\n", prim_poly(i));
    break;
  endif
endfor
