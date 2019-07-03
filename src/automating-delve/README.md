
These are the programs used for the experiments in the [automating
delve][blog-post] blog post.

## Counter

Counter is a basic program that will increment a counter as fast as possilbe
and report on the rate at which it was incremented. This is used for
demonstrating the performance impact of different insturmetation.

## Low Hz

LowHZ uses delve to measure the global counter variable of the counter process
once every second and reports on the rate it is being incremented at. This is
an examle of low frequency instrumentation.

## High Hz

HighHZ uses delve to measure the global counter variable of the counter
process every time it is incremented and reports on the rate it is being
incremented at. This is an examle of high frequency instrumentation.

## Proxy

Proxy is a transparent TCP proxy that you can stick in between two ends of a
connection. It will read individual lines from both ends, report those lines
to stdout, and write them to the other end.

This was useful in snooping on the API commands that `dlv connect` sends to
`dlv attach --headless`.

[blog-post]: https://wat.io/posts/automating-delve/
