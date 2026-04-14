import fitz
import os

pdf_path = "PoisonChain.pdf"
output_dir = "slides"

os.makedirs(output_dir, exist_ok=True)
doc = fitz.open(pdf_path)

# Use 4.0 zoom for high-quality rendering
mat = fitz.Matrix(4.0, 4.0)

for i in range(len(doc)):
    page = doc.load_page(i)
    pix = page.get_pixmap(matrix=mat)
    output_file = os.path.join(output_dir, f"Slide{i+1}.png")
    pix.save(output_file)
    print(f"Saved {output_file}")
