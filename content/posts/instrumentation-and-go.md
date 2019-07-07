---
title: "Instrumentation and Go"
date: 2019-06-25T10:27:18-06:00
description: |
    What is instrumentation? What kinds of instrumataion are available for Go
    programs and when should you use them? What is dynamic instrumentation?
---

Instrumentation is anything that allows you to make measurements. For example
the speedometer in your car that measures your velocity or the smoke detector
in your house that measures how good of a cook you are. Instrumentation
collects hard facts that you can use to understand and explain the world.
Instrumentation is critical to our understanding of software.

In this series of posts we will walk through several techniques for
instrumenting Go programs. Most of these will generalize to other languages
but I put a special emphasis on Go since it has some unique challenges and it
is the language I am most experienced with.

## Animalcules and Atoms

One of my favorite stories is about the development of the microscope. In
1676, a Dutch cloth merchant named Antonie van Leeuwenhoek improved the design
of the early microscope in order to inspect the fibers of clothing that he
sold. His microscope was way better than any that previously existed because
of the lenses he used. He was able to see clear, focused images of high
magnification for the first time!

He used his microscope to study the water in Holland. He discovered that the
water was infested with little creatures, single-celled organisms that he called
kleine diertgens, or as they were called in English: animalcules. I love that
name, it's so adorable!

<img src="/images/animalcules.png" data-animated-src="/images/animalcules.gif" class="hover-gif" />

By developing this new instrument Antonie was able to observe the microcosm
of life previously invisible to the human eye. He discovered bacteria, red
blood cells, spermatozoa, and muscle fibers. Can you imagine living in a world
where no one knew that bacteria existed, or that they could cause disease? That
is the world we lived in for a majority of our existence. The microscope
changed all that!

Microbiology has a **hard** dependency on the microscope. Without the
microscope, we could not have developed the germ theory of disease and modern
medicine would not exist.

![][dependency-graph]

A new kind of instrumentation was required to achieve a new level of
understanding.

Modern microscopes can see soo far into the world of the small that we can
image individual atoms. I recently learned about a movie that was made by IBM
research called "[A Boy and His Atom][a-boy-and-his-atom]" where each frame was
created by imaging carbon monoxide molecules using a scanning tunneling
microscope.

<img src="/images/a-boy-and-his-atom.png" data-animated-src="/images/a-boy-and-his-atom.gif" class="hover-gif" />

This is incredibly awesome! This instrument allows us to study the surface
properties of materials. It is an important tool in research into
semiconductors and microelectronics.

Again, new kinds of instrumentation are required to achieve new levels of
understanding.

## Instrumentation in Software

In software, instrumentation allows us to make measurements of our systems and
understand their execution and behavior. This understanding not only allows
us to solve problems, ideally before they occur, but also helps us grow as
software practitioners, learning more about how systems interoperate with the
software we write.

I like to divide software instrumentation into a hierarchy with three main
categories:

### Static and Always On

This type of instrumentation is what you are likely most familiar with. You add
it to your source code in advance and it is always running, making
observations. The [observer effect][observer-effect] ensures that this is not
free of cost. You pay a performance penalty for all measurements. As a
result, you can not cover every part of your system. Some examples of this kind
of instrumentation are:

- Logging
- Metrics
- Distributed Tracing

These forms of instrumentation are incredibly valuable and are usually the
first place to look when investigating a problem.

### Static and Requires Activation

This type of instrumentation you also add to your source code in advance.
However, since it is not always running you can cover more of your system and
only pay the performance cost when you enable it. Examples include:

- Leveled Logging
- pprof
- USDT Probes

### Dynamic

With static instrumentation, you have to know, in advance, what sort of
questions you might want to ask of your system. This is a major disadvantage.
When you have a running program that you want to measure, if you did
not think of the proper instrumentation in advance, you will have to add more
instrumentation to the code, re-compile, and redeploy/restart. This can lead to
a frustratingly slow iteration cycle when debugging. If it took three weeks
for the system to get into a failing state, waiting another three weeks to get
an answer to a question is unacceptable.

We need a new kind of instrumentation to achieve a new level of understanding!

This is where dynamic instrumentation comes into play. The goal of dynamic
instrumentation is to add instrumentation logic to a running program, without
it knowing. Nothing special needs to be done in advance, any binary the Go
compiler produces should work.

## Streetlight Effect

The "streetlight effect" is an excellent analogy that illustrates the benefits
of dynamic instrumentation. If you are unfamiliar with the story, there is a
man looking for his wallet under a streetlight. A cop stops to help the man.
After some time looking under the streetlight, the cop asks the man if this is
where he lost his wallet. He says "No, I lost it in the park but this is where
the light is."

![][streetlight-effect]

Understandably, it is silly for the man to be looking under the streetlight.
However, what are his alternatives, wander aimlessly in the dark?

In this analogy, the streetlight is an example of static instrumentation. If the
man lost his wallet under one of those streetlights then he is all set.
Similarly, if the problem you are investigating is covered by your static
instrumentation then no problem.

In the case where the man lost his wallet in the park, he really just needs a
flashlight to go looking for it. That is what dynamic instrumentation is, a
flashlight that you can shine on any part of your system, as it is running, and
collect the data that you need.

The other day I ran across a [thread][thread] on the golang-devs mailing
list where Rob Pike and others were discussing this stuff. Rob said:

> I want a toolkit that can examine running programs and answer questions about
> them. Questions I don't know until the problem arises...

> I'd like not to require compilation-time changes. I'd like to come to an
> arbitrary program while it's running...

> I want a programming interface above which I can build whatever is needed,
> either generally-useful tools or ad hoc probes. And the programming language
> I want to use for this is Go.

What Rob wants is a flashlight. Unfortunately, I don't believe a toolkit that
matches his specific criteria exists, yet. However, there have been many
advances since this discussion that provide a good deal of capability.

In the next few posts on this topic, I will cover techniques that I have used to
dynamically instrument Go programs. These include:

- [Automating Delve][automating-delve]
- uprobes and BPF
- Frida

I have gotten a good deal of benefit out of using these techniques, I hope you
do as well. Stay tuned!

[a-boy-and-his-atom]: https://www.youtube.com/watch?v=oSCX78-8-q0
[observer-effect]: https://en.wikipedia.org/wiki/Observer_effect_(information_technology)
[thread]: https://groups.google.com/d/msg/golang-dev/m0Q60EEydX0/pRBY6BrShqcJ

[dependency-graph]: /images/dependency-graph.png
[streetlight-effect]: /images/streetlight.png
[automating-delve]: /posts/automating-delve/
