# pwn
Password checker using the https://haveibeenpwned.com/Passwords API

## Usage
- Run pwn.exe interactively and enter passwords to be manually checked.
- Feed it a line separated password file with the flag `-f`

    `pwn.exe -f password-file.txt`
- Drag and drop a text file on to the executable.

The program will create a result file in the same folder as your text file when using a password file.
The format of the results will be:
```
<password>:<count>
```
A count of 0 means there are no matches.