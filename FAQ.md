# How do I add a domain to the blacklist/whitelist? #

You can just add plain old domain names to the list, one per line, and it'll work fine. Like so:

```
evilspammer.com
anotherspammer.com
naughtyspammer.com
```

It's not necessary to include the `www.` portion of the domain name. If you do, ReferrerCop will just ignore it.

You can also use regular expressions by surrounding the entry with front-slashes:

```
/(?:evil|another|naughty)spammer.com/
```

# Is it possible to add a specific URL to the blacklist/whitelist rather than an entire domain? #

Yep. Just add the URL in the following format:

```
example.com/foo/bar.html
```

# Where do the entries in the default blacklist come from? #

I (the author) manually update and verify the list based on referrer spam received by various sites I administer, as well as those hosted by [Jetpants](http://jetpants.com/).

# I have a shared hosting package with a web-based control panel. Can I install ReferrerCop on my account? #

Probably not, but it depends on the host. At this time, the only shared host we know of that provides ReferrerCop filtering is [Jetpants](http://jetpants.com/). You might want to try asking your administrator if they'll install ReferrerCop for you.
