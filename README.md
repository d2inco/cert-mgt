
Quick script to manage/maintain a self-managed Certificate Authority and to create
certificates under that CA.

First, copy the cert-mgt.conf-sample to cert-mgt.conf and make changes in there as
appropriate for your environment.

Then, to create the CA:
```
    ./cert-mgt.sh --create-ca
```

To create all certificates referenced in the config file:
```
    ./cert-mgt.sh --create-cert all
```

Or, to create certificates 1 by 1:
```
    ./cert-mgt.sh --create-cert example.com
```

or with Subject Alternative Names:
```
    ./cert-mgt.sh --create-cert example.com --add-on "www.example.com test.example.com"
```
