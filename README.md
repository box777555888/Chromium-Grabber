# Chromium-Grabber
Decrypts and prints saved local browser passwords  
Runs on windows only (for now)

# Preview

```
python recon_browser_passwd.py 3
```
```
Domain: https://something.google.com/
Username: xxx
Password: xxx
--------------------------------------------------------------------------
Domain: https://id.somewebsite.com/
Username: xxx
Password: xxx
--------------------------------------------------------------------------
...
```

# Usage
```
usage: recon_browser_passwd.py [-h] [{1,2,3}]

Enumerate saved passwords from Chrome, Brave, or Edge.

positional arguments:
  {1,2,3}     Choose a browser: 1.Chrome 2.Brave 3.Edge

options:
  -h, --help  show this help message and exit
```

