## Brute force a BCH polynomial knowing syndrome outputs
pkg load signal
pkg load communications
clear

# Inputs
target_code00s = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
target_codeFFs = [1,1,0,1,0,1,1,1,1,1,1,0,1,1,0,0,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,1,0,0,1,0,1,0,1,0,0,1,1,1,0,0,0];
eccsize = 512
eccstrength = 4

# Useful definitions
min_m = 5;
eccsizeb = 512 * 8;
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
      k = npoly(i,2) # Just set k and skip this function when you know it
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
