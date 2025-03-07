# IBKR Authentication Workflow

Documentation for the IBKR Web API is [here](https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-ref/).

1. Pull the repository.
2. Create and activate a virtual environment.
3. Install dependencies from `requirements.txt`.
4. Create a YAML configuration file:

    ```yaml
    client_id: ""
    client_key_id: ""
    credential: ""
    private_key_file: ""
    ```

    The private key file will usually have a `.pem` extension.
5. Run the test script.

    ```bash
    python auth.py
    ```
