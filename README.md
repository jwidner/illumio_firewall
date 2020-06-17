Note
----
This is a small take home project I made for an Illumio internship I
applied for about 17 months ago at the time of writing (so around January
2019). I'm making this public to show case my programming ability. Everything
below this note were questions asked by the Illumio team.

Testing
-------
Running the file 'test.py' with the Python interpreter runs the test cases
that I wrote for this coding assignment. The first test case is the same
as the example one given in the instructions. The handwritten test cases
are in folders: ./test_inputs and ./test_outputs . The dynamic test cases
generate files and then run the firewall on the generated files. Although
we can't programatically test correctness of the firewall without having a
correct reference implementation, we can use these tests to benchmark the
performance of the firewall on repeated data and on randomly generated data.
If I had more time, I would have made sure to time the separate parts of the
tests, i.e. how long it takes to build the data structure, and then how long
each query takes. Right now, I only have how long all of the tests take, and
they seem to take a reasonable amount of time.

Design Choices
--------------
I have used a Python set to store the policies/rules because this ensures that
no duplicate policies end up being stored. Furthermore, I have augmented
the data structure to keep track of the global minimum and maximum of the
port numbers and ip addresses stored in the set. This way, some lookups
end up taking O(1) time because they are outside the possible range of
accepted values stored in the set. The average/worst case lookup takes O(n)
time where n is the number of policies stored. We can also note that it takes
O(n) time to build the data structure. I am confident that it's possible
to have a sublinear lookup time in the worst case, and I outline why below.

Possible Improvements
---------------------
The obvious bottleneck in the program is the amount of time it takes
to query (and build) the data structure holding the policies (PolicyGroup)
I'm fairly convinced that it's possible to design a data structure
to hold the policy information that allows for O(log n) lookups (to
decide if a packet should be accepted or not) in the worst case where
n is the number of policies in the data structure. However, it's not
clear to me how to design such a (balanced) binary search tree, for example, to
accomplish this task. The reason I think that something like this is possible
is that this problem is essentially the opposite of a range search, where
instead of finding a key that is in some range, we're finding some range
to match our key (and we must do this for two separate ranges and keys in combination).
If a binary search tree solution works for this problem, we might even prefer
to use a Van Emde Boas tree because IPv4 addresses are 32 bits wide, and
there might be a large number of policies in the data structure.

We might also try to reduce the number of policies by finding ways to identify
and combine policies that are able to be combined. For example, if A and B are policies,
and A is entirely contained in B (B contains all ip/port range combinations that A has),
we can delete A without affecting how the firewall functions. A naive solution to this
problem would take O(n^2) time by considering all policy pairs.
