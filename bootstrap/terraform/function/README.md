# Azure Function terraform setup

This directory contains terraform configuration to setup an Azure Function and
its dependencies to test the Vault Azure auth method.

## Overview

### Terraform

The Terraform configuration will create:

- A service principal with necessary role assignments
- A resource group, which is a logical container for related resources
- A storage account, which maintains the state and other information about your projects
- A function app, which provides the environment for executing your function code
- A user-assigned managed identity, which the Azure function will use to acquire a JWT

### Python function

Inside the `function-project` directory is the `vlt-auth-func-test` directory
that holds our Azure function to be used for testing the Vault Azure auth
method.

```
├── function-project
│   ├── requirements.txt
│   └── vlt-auth-func-test
│       ├── __init__.py
```

The `__init__.py` file contains the code that will execute when we invoke our
Azure function. This project was created with the help of the Azure Functions
Core Tools CLI following
[this guide](https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-cli-python).

## Prerequisites

- Logged into Azure with an active subscription.
  ```
  az login
  ```

### Development prerequisites
- Python version 3.9.x
  ```
  python --version (Linux/macOS)
  py --version (Windows)
  ```
- [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local#v2) version is 4.x.
  ```
  func --version
  ```
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) version is 2.4 or later.
  ```
  az --version
  ```

If you are modifying the python Azure function code locally you should create a
python virtual environment in the `function-project` directory. This will be
ignored by source control.
```
python -m venv .venv
```

## Setup Terraform env

```
terraform apply
```

## Publish Azure function

```
./publish.sh
```

## Test with Vault Azure auth method

Source the `local_environment_setup.sh` file to export the needed environment variables:
```
source ./local_environment_setup.sh
```

Start the Vault server and the run the `configure.sh` script:
```
./configure $PLUGIN_DIR $PLUGIN_NAME $PLUGIN_PATH
```

This script will query the Azure function to fetch the JWT to be used on Vault
login.

## Updating the Changelog

All pull requests that introduce a user-facing change must include a changelog
entry. We use the [changie](https://changie.dev/) tool to manage these entries
and automate the release process.

---
### 1. Installing Changie

You only need to do this once. If you don't have `changie` installed, choose one of the options below.

* **Homebrew** (macOS):
    ```shell
    brew install changie
    ```
* **Go Install**:
    ```shell
    go install github.com/miniscruff/changie@latest
    ```
* **Other Methods**:
  See the [official changie installation guide](https://changie.dev/guide/installation/) for other options, including pre-compiled binaries.

---
### 2. Creating an Entry

Once your code changes are complete, create the changelog entry:

1.  **Run the command** in your terminal:
    ```shell
    changie new
    ```
2.  **Follow the prompts.** An interactive prompt will ask you to select the
    kind of change (e.g., `BREAKING CHANGES`, `NOTES`, `FEATURES`) and write a concise description of
    what you changed.

3.  **Commit the new file.** After you're done, `changie` will create a new
    YAML file in the `.changie/unreleased` directory. Commit this file along with your other
    code changes before submitting your pull request.
