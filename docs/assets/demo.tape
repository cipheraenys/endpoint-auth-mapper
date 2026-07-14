Output docs/assets/demo.gif

Set FontSize 14
Set Width 120
Set Height 35
Set Theme "Dracula"

Type "authmap --project . --interactive"
Enter
Sleep 2s

# Navigate down a few times
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 500ms

# Open help overlay
?
Sleep 2s

# Close help
?
Sleep 500ms

# Toggle search
/
Sleep 500ms
Type "admin"
Sleep 1s

# Clear search and exit
Escape
Sleep 500ms
q
