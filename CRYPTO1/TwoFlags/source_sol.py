import numpy as np
from PIL import Image, ImageEnhance
 
enc1 = Image.open("flag_enc.png")
enc2 = Image.open("notflag_enc.png")
 
enc1np = np.array(enc1).astype(np.int16)
enc2np = np.array(enc2).astype(np.int16)
 
# enc1 XOR enc2 = (flag XOR key) XOR (notflag XOR key) = flag XOR notflag
xor_result = np.bitwise_xor(enc1np, enc2np).astype(np.uint8)
img = Image.fromarray(xor_result)
img.save("xor_result.png")
 
print("Done! Output: xor_result.png")
