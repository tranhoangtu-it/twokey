# Demo GIF for the README: `vhs demo.tape` (https://github.com/charmbracelet/vhs)
Output docs/demo.gif
Set FontSize 18
Set Width 1200
Set Height 640
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Type "twokey replay pocketos"
Sleep 400ms
Enter
Sleep 4s

Type "twokey explain --method DELETE --url https://api.github.com/repos/acme/prod-api; echo exit=$?"
Sleep 400ms
Enter
Sleep 3s

Type "twokey explain --method GET --url https://api.github.com/repos/acme/prod-api"
Sleep 400ms
Enter
Sleep 3s
