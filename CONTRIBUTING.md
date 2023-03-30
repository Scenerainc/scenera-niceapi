# Contributing Guide

## Issue Tracker
We use an issue tracker hosted in the niceapi GitHub repository. If you encounter any bugs, or come up with any feature requests, please first search if there is an already existing issue. If you can not find any, please feel free to post a new issue.

## Contributing by Pull Request
We appreciate contributors in the community, that are willing to improve niceapi. 
We basically follow the development style used in many GitHub repositories.
1. Search existing issues and/or pull request in the GitHub repository.
2. If it doesn't exist, post an issue for the feature proposal.
3. Fork the repository, and develop your feature in the forked repo.
4. Format your code. (Refer: Auto format guidelines section below)
5. linting your code. (Refer: linting guidelines section below)
6. Test your code. (Refer: test guidelines section below)
7. Make document.(Refer: document guidelines section below)
8. Create a pull request of your development branch to niceapi's master branch. Our maintainers will then review your changes.
9. Once your change is finalized, the maintainer will merge your change.

## Contributing code
It is highly recommended to format, linting and test your changed code before opening pull requests, which will save your and the reviewers' time.

### Formatting Guidelines
We use isort and black to automatically format Python code.

#### Running AutoFormat
Run following command to apply auto formatting for code.
```sh
cd {niceapi repository root}
make format
```

### Linting Guidelines
We use flake8, mypy and bandit to check code consistency and type annotations. Run flake8, mypy and bandit to check that your implementation does not raise any error.

#### Running Linting
Run following command to Static Analysis
```sh
cd {niceapi repository root}
make lint
```

### Test Guidelines
We use pytest and pytest-cov to unittest.

#### Writing unit test
If there is no existing test that checks your changes, please write a test(s) to check the validity of your code. Any pull request without unit test will NOT be accepted.When adding a new unit test file, place the unit test file under the tests/ directory with name test_<the file name to test>.py. 
See the below example.

Example: When adding tests for your_new_file.py placed under nnabla_rl/utils.

```
.
├── ./src
│   └── ./src/niceapi
│       └── ./src/niceapi/util
│           └── ./src/niceapi/util/your_new_file.py
│
└── ./tests
    └── ./tests/niceapi
        └── ./tests/niceapi/utils
            └── ./tests/niceapi/utils/your_new_file.py
```

Use pytest-cov to get coverage.
C1 coverage should be 100%.

#### Running Test
You can run tests with the following command.
```sh
cd {niceapi repository root}
make test
```

### Document Guidelines
We use the document generation tool Sphinx to automatically generate documents from docstrings of Python script classes and functions.
Add docstring as needed and Check that there are no errors in document generation.

#### Generate Documents
You can Generate Documents with the following command.
```sh
cd {niceapi repository root}
make docs
```

**Note:** The following tools must be installed to generate the document.  
plantuml (https://github.com/plantuml/plantuml/releases) >= 1.2018.13  
pandoc (https://github.com/jgm/pandoc/releases) >= 2.5  

Installation example (for ubuntu 18.04)
```
sudo apt purge plantuml pandoc

sudo wget https://github.com/plantuml/plantuml/releases/download/v1.2022.2/plantuml-1.2022.2.jar -O /opt/plantuml.jar
sudo tee /usr/local/bin/plantuml <<EOF >/dev/null
#!/bin/sh -e
java -jar /opt/plantuml.jar "\$@"
EOF
sudo chmod +x /usr/local/bin/plantuml

wget https://github.com/jgm/pandoc/releases/download/2.17.1.1/pandoc-2.17.1.1-1-amd64.deb
sudo dpkg -i pandoc-2.17.1.1-1-amd64.deb
```