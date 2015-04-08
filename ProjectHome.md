# Overview #

ReferrerCop parses Apache log files and AWStats data files and removes entries for referring URLs that match a list of known referrer spammers. Filtering is performed using a blacklist and an optional whitelist.

A large default blacklist is provided with the software, and you can run `referrercop -U` to download the latest blacklist.

If you're a Ruby programmer, you can easily integrate ReferrerCop's functionality into your own tools. See the API documentation for details.

# Requirements #

  * [Ruby](http://www.ruby-lang.org/) 1.8.5+

# Usage #

```
referrercop [-f | -i | -n | -s] [options] [<file> ...]
referrercop -u <url> [options]
referrercop -U [options]
referrercop {-h | -V}

Modes:

 -f, --filter             Filter the specified files (or standard input if no
                          files are specified), sending the results to
                          standard output. This is the default mode.
 -i, --in-place           Filter the specified files in place, replacing each
                          file with the filtered version. A backup of the
                          original file will be created with a .bak extension.
 -n, --extract-ham        Extract ham (nonspam) URLs from the input data and
                          send them to standard output. Duplicates will be
                          suppressed.
 -s, --extract-spam       Extract spam URLs from the input data and send
                          them to standard output. Duplicates will be
                          suppressed.
 -u, --url <url>          Test the specified URL.
 -U, --update             Check for an updated version of the default
                          blacklist and download it if available.

Options:

 -b, --blacklist <file>   Blacklist to use instead of the default list.
 -c, --config <file>      Use the specified config file.
 -v, --verbose            Print verbose status and statistical info to stderr.
 -w, --whitelist <file>   Whitelist to use instead of the default list.

Information:

 -h, --help               Display usage information (this message).
 -V, --version            Display version information.
```