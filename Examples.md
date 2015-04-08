# Filter an Apache log file using the default blacklist #
```
# referrercop /var/log/httpd-access.log > filtered.log
```

# Filter an Apache log file and display statistics #
```
# referrercop -v /var/log/httpd-access.log > filtered.log
ReferrerCop v1.0.4 <http://wonko.com/software/referrercop/>
Copyright (c) 2005 Ryan Grove <ryan@wonko.com>.

Using blacklist ./blacklist.refcop
Compiled 37 blacklist patterns.
Input type: Apache combined log file
Processed 23605 lines in 1.63815021514893s (14410 lines per second)
23142 ham, 463 spam, 0 invalid
```

# Filter an AWStats data file using a custom whitelist #
```
# referrercop -w whitelist.txt /var/cache/awstats/awstats062005.txt > filtered.txt
```

# Filter several Apache log files in place #
```
# referrercop -i /var/log/foo.com-access.log /var/log/bar.com-access.log
```

# Filter Apache log files in place by wildcard #
```
# referrercop -i /var/log/*-access.log
```

# Display the status of a single URL #
```
# referrercop -u http://wonko.com/
Ham
```