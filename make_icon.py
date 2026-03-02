from PIL import Image, ImageDraw

SIZE = 1024
img = Image.new('RGBA', (SIZE, SIZE), (11, 11, 13, 255))
d = ImageDraw.Draw(img)

# Subtle border glow
for i, a in [(0, 40), (8, 25), (16, 15)]:
    d.rounded_rectangle((40+i, 40+i, SIZE-40-i, SIZE-40-i), radius=220, outline=(242,106,27,a), width=3)

# Shield shape
shield = [
    (SIZE*0.5, SIZE*0.14),
    (SIZE*0.78, SIZE*0.24),
    (SIZE*0.78, SIZE*0.53),
    (SIZE*0.5, SIZE*0.82),
    (SIZE*0.22, SIZE*0.53),
    (SIZE*0.22, SIZE*0.24),
]
d.polygon(shield, fill=(24, 27, 31, 255), outline=(242, 106, 27, 255), width=28)

# Lock body
d.rounded_rectangle((360, 430, 664, 680), radius=42, fill=(242, 106, 27, 255))
# Lock shackle
d.arc((390, 300, 634, 560), start=200, end=-20, fill=(242, 106, 27, 255), width=36)

# Pixel grid (steganography hint)
cell = 46
gap = 12
start_x = 414
start_y = 486
for r in range(3):
    for c in range(3):
        x0 = start_x + c * (cell + gap)
        y0 = start_y + r * (cell + gap)
        color = (244, 242, 235, 255)
        if r == 1 and c == 2:
            color = (255, 126, 53, 255)
        d.rounded_rectangle((x0, y0, x0 + cell, y0 + cell), radius=8, fill=color)

img.save('icon-1024.png')
print('wrote icon-1024.png')
