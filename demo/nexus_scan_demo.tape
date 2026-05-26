# vhs tape for the PoisonChain Nexus scan demo GIF.
#
# Layout convention:
# - Recorded media (.tape, .gif) lives under demo/ so it does not clutter
#   scripts/, which is reserved for executable code.
# - The replay script invoked inside the recording lives at
#   scripts/nexus_scan_replay.py so the path shown in the GIF mirrors the
#   real CLI location (scripts/), not the recording folder.
#
# Render with: vhs demo/nexus_scan_demo.tape
# Output:      demo/nexus_scan_demo.gif

Output demo/nexus_scan_demo.gif

# Rendered at 2x the intended display size (display target: 550x356) so the
# GIF looks crisp when README embeds it via <img width="550">. Keeping the
# native bitmap at this ratio gives the retina-style anti-aliasing that 1:1
# 550x356 rendering visibly lacks.
Set Shell "bash"
Set FontSize 20
Set Width 1100
Set Height 712
Set Padding 12
Set Framerate 60
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set PlaybackSpeed 1.0

# Set up an invisible bash function so that the *displayed* command
# `python3 scripts/nexus_proxy_scan.py` actually executes the sanitized
# replay at scripts/nexus_scan_replay.py. The real scanner script
# (scripts/nexus_proxy_scan.py) is untouched and never invoked here —
# it requires Nexus credentials and would call out to the live registry.
Hide
Type `python3() { if [[ "$1" == "scripts/nexus_proxy_scan.py" ]]; then command python3 scripts/nexus_scan_replay.py "${@:2}"; else command python3 "$@"; fi; }`
Enter
Type "clear"
Enter
Show

# Cold-open: the canonical scan command exactly as a real user would type it.
Type "python3 scripts/nexus_proxy_scan.py --include-compromised"
Sleep 600ms
Enter

# Let the replay run to completion. The replay itself paces the progress
# bar over ~6s; the rest of the output is near-instant.
Sleep 9s

# Hold the final frame so viewers can read the summary.
Sleep 2500ms
