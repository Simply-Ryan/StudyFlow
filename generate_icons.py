"""
Icon Generator for StudyFlow PWA
Generates placeholder icons in various sizes
"""
from PIL import Image, ImageDraw, ImageFont
import os

# Create icons directory
icons_dir = 'static/icons'
os.makedirs(icons_dir, exist_ok=True)

# Icon sizes required for PWA
sizes = [72, 96, 128, 144, 152, 192, 384, 512]

# Create icons
for size in sizes:
    # Create image with gradient background
    img = Image.new('RGB', (size, size), color='#667eea')
    draw = ImageDraw.Draw(img)
    
    # Add gradient effect (simple diagonal)
    for i in range(size):
        for j in range(size):
            # Calculate gradient
            r = int(102 + (118 - 102) * (i + j) / (2 * size))
            g = int(126 + (75 - 126) * (i + j) / (2 * size))
            b = int(234 + (162 - 234) * (i + j) / (2 * size))
            img.putpixel((i, j), (r, g, b))
    
    # Add text "SF"
    draw = ImageDraw.Draw(img)
    try:
        # Try to use a nice font
        font_size = int(size * 0.4)
        font = ImageFont.truetype("arial.ttf", font_size)
    except:
        # Fallback to default font
        font = ImageFont.load_default()
    
    text = "SF"
    # Get text bounding box
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    # Center text
    x = (size - text_width) / 2
    y = (size - text_height) / 2
    
    # Draw text with shadow
    draw.text((x+2, y+2), text, fill=(0, 0, 0, 100), font=font)
    draw.text((x, y), text, fill='white', font=font)
    
    # Save icon
    filename = f'{icons_dir}/icon-{size}x{size}.png'
    img.save(filename, 'PNG')
    print(f'✅ Generated {filename}')

print(f'\n🎉 Generated {len(sizes)} icons successfully!')
