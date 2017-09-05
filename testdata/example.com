@   IN      SOA     nslab   admin.git.example.com (
                                 20      ; SERIAL
                                 7200    ; REFRESH
                                 600     ; RETRY
                                 3600000 ; EXPIRE
                                 60)     ; MINIMUM

            NS      nslab
            MX      10  mail01
            MX      20  mail02

nslab       A       10.100.1.2
mail01      A       10.100.1.3
            A       10.101.1.3
mail02      A       10.100.1.4
