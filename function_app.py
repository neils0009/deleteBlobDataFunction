import os
import datetime
import logging
import azure.functions as func

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp()

def get_connection_string_from_key_vault():
    
    key_vault_name = os.environ.get("KEY_VAULT_NAME")
    secret_name = os.environ.get("STORAGE_CONN_STRING_SECRET_NAME")

    if not key_vault_name:
        raise ValueError("Environment variable 'KEY_VAULT_NAME' is not set.")
    if not secret_name:
        raise ValueError("Environment variable 'STORAGE_CONN_STRING_SECRET_NAME' is not set.")


    kv_uri = f"https://{key_vault_name}.vault.azure.net"
    
    logging.info (f"vault URI is <{kv_uri}>")

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=kv_uri, credential=credential)

    return client.get_secret(secret_name).value

#@app.timer_trigger(schedule="0 * * * * *", arg_name="myTimer", run_on_startup=False, use_monitor=False)
@app.timer_trigger(schedule="0 0 8 * * *", arg_name="myTimer", run_on_startup=False, use_monitor=False)
def deleteBlobDataFunction(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function started.')

    try:
        container_name = os.environ.get("CONTAINER_NAME")
        if not container_name:
            raise ValueError("Container name not found")
    
        logging.info(f"The container name is <{container_name}>")
        
        conn_str = get_connection_string_from_key_vault()
        blob_service_client = BlobServiceClient.from_connection_string(conn_str)
        container_client = blob_service_client.get_container_client(container_name)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        expiry_threshold = now_utc - datetime.timedelta(days=1)

        for blob in container_client.list_blobs():
            logging.info(f"Checking blob: <{blob.name}> (Last Modified: <{blob.last_modified}>)")
            if blob.last_modified < expiry_threshold:
                logging.info(f"Deleting blob: <{blob.name}> (Last Modified: <{blob.last_modified}>)")
                container_client.delete_blob(blob.name)

        logging.info('Blob cleanup completed successfully.')

    except Exception as e:
        logging.error(f"Error during blob cleanup: <{str(e)}>")
