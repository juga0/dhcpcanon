Contributing to `dhcpcanon`
===========================

We welcome contributions of any kind (ideas, code, tests, documentation,
examples, ...).

General contribution guidelines
-------------------------------

-   Any non-trivial change should contain tests.
-   All the functions and methods should contain Sphinx docstrings which
    are used to generate the API documentation.

Code style guide
----------------

-   We follow [PEP8 Python Style
    Guide](http://www.python.org/dev/peps/pep-0008/)
-   Use 4 spaces for a tab
-   Use 79 characters in a line
-   Make sure edited file doesn't contain any trailing whitespace
-   You can verify that your modifications don't break any rules by
    running the `flake8` script - e.g. `flake8 dhcpcanon/edited_file.py`
    or `tox -e style`. Second command will run flake8 on all the files
    in the repository.

And most importantly, follow the existing style in the file you are
editing and **be consistent**.

Docstring conventions
---------------------

For documenting the API we we use Sphinx and reStructuredText syntax.

Contribution workflow
---------------------

### 1. Open a new issue on our issue tracker

Go to our [issue tracker](https://github.com/juga0/dhcpcanon/issues) and
open a new issue for your changes there.

### 2. Fork our Github repository

Fork our [Github git repository](https://github.com/juga0/dhcpcanon).
Your fork will be used to hold your changes.

### 3. Create a new branch for your changes

For example:

### 4. Make your changes

Commit often and rebase master

### 5. Write tests for your changes and make sure all the tests pass

Make sure that all the code you have added or modified has appropriate
test coverage. Also make sure all the tests including the existing ones
still pass using `tox`

### 6. Open a Pull request

You can then push your feature branch to your remote and open a pull
request.

> **note**
>
> Partly copied from [libcloud
> contributing](https://libcloud.readthedocs.io/en/latest/development.html#contributing)
