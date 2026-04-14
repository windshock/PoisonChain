import os
import subprocess
import concurrent.futures

segments = [
    {"slide": 1, "duration": 120.5, "effect": "static"},
    {"slide": 2, "duration": 81.0, "effect": "static"},
    {"slide": 3, "duration": 98.0, "effect": "static"},
    {"slide": 6, "duration": 20.0, "effect": "static"},
    {"slide": 7, "duration": 320.0, "effect": "zoom in"},
    {"slide": 5, "duration": 122.0, "effect": "static"},
    {"slide": 8, "duration": 452.0, "effect": "pan right"},
    {"slide": 9, "duration": 258.0, "effect": "zoom in"},
    {"slide": 10, "duration": 106.0, "effect": "static"},
    {"slide": 14, "duration": 141.0, "effect": "static"},
    {"slide": 11, "duration": 180.0, "effect": "static"},
    {"slide": 4, "duration": 34.0, "effect": "static"},
    {"slide": 5, "duration": 105.0, "effect": "static"},
    {"slide": 15, "duration": 166.0, "effect": "zoom in"},
    {"slide": 12, "duration": 117.0, "effect": "static"},
    {"slide": 18, "duration": 248.0, "effect": "static"},
    {"slide": 5, "duration": 186.0, "effect": "static"},
    {"slide": 1, "duration": 46.5, "effect": "static"}
]

os.makedirs("parts", exist_ok=True)

def render_segment(i, seg):
    out_file = f"parts/part_{i:02d}.mp4"
    if os.path.exists(out_file):
        os.remove(out_file)
        
    slide_file = f"slides/Slide{seg['slide']}.png"
    dur = seg['duration']
    frames = int(dur * 30)
    
    cmd = [
        "/opt/homebrew/bin/ffmpeg", "-y",
        "-loop", "1", "-framerate", "30",
        "-i", slide_file
    ]
    
    # Scale first to base 1080p, then apply effect
    base_scale = "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:-1:-1:color=black"
    
    if seg['effect'] == "static":
        cmd += [
            "-vf", base_scale,
            "-t", str(dur)
        ]
    elif seg['effect'] == "zoom in":
        r = 0.15 / frames
        cmd += [
            "-vf", f"{base_scale},zoompan=z='min(1.15, 1.0+{r:.7f}*on)':x='iw/2-(iw/zoom)/2':y='ih/2-(ih/zoom)/2':d={frames}:s=1920x1080",
            "-t", str(dur)
        ]
    elif seg['effect'] == "pan right":
        cmd += [
            "-vf", f"{base_scale},zoompan=z=1.15:x='(iw-iw/zoom)*(on/{frames})':y='(ih-ih/zoom)/2':d={frames}:s=1920x1080",
            "-t", str(dur)
        ]
        
    cmd += [
        "-c:v", "libx264", "-preset", "ultrafast", "-crf", "18",
        "-pix_fmt", "yuv420p", out_file
    ]
    
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Finished {out_file}")
    return out_file

print("Starting video rendering (this may take a while)...")
# Render 4 parts at a time
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(render_segment, i, seg) for i, seg in enumerate(segments)]
    concurrent.futures.wait(futures)

print("Writing concat demuxer file...")
with open("concat.txt", "w") as f:
    for i in range(len(segments)):
        f.write(f"file 'parts/part_{i:02d}.mp4'\n")

print("Concatenating parts with audio...")
concat_cmd = [
    "/opt/homebrew/bin/ffmpeg", "-y",
    "-f", "concat", "-safe", "0",
    "-i", "concat.txt",
    "-i", "The_Three_Hour_North_Korean_Axios_Breach.m4a",
    "-c:v", "copy",
    "-c:a", "aac", "-b:a", "192k",
    "-shortest",
    "final_youtube_video.mp4"
]
subprocess.run(concat_cmd)
print("Done! final_youtube_video.mp4 created successfully.")
