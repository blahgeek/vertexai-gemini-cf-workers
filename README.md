# vertexai-gemini-cf-workers

A Cloudflare workers to proxy Gemini on Vertex AI. Compare to Google AI, Vertex AI use IAM access instead of API key. Therefore, a custom API key is required to authenticate user.

## How-to

1. Sign up for a GCP account:
   - Go to [https://cloud.google.com/vertex-ai](https://cloud.google.com/vertex-ai) and sign up for a GCP account.
   - You can get $150 free credits without a credit card, or $300 free credits by providing a credit card. (Note that the free credits expire in 90 days)

2. Enable Vertex AI API:
   - Go to [https://console.cloud.google.com/marketplace/product/google/aiplatform.googleapis.com](https://console.cloud.google.com/marketplace/product/google/aiplatform.googleapis.com) to enable the Vertex AI API for your project.
   
3. Create a [Service Account](https://console.cloud.google.com/projectselector/iam-admin/serviceaccounts/create?walkthrough_id=iam--create-service-account#step_index=1):
   - Select the project ID you created earlier.
   - Make sure to grant the role of "Vertex AI User" or "Vertex AI Administrator" to the service account.
   - On the service account page you just created, go to the "Keys" tab and click "Add Key".
   - Select "Create new key" and choose "JSON" as the key type.
   - The key file will be downloaded automatically. This file contains the required variables for the worker, such as project_id, private_key, and client_email.
   
4. Clone this project to your own github repo.

5. Create a cloudflare page project, connect to your github repo.
   - Set Deploy Command to `npx wrangler deploy --keep-vars` (this is important if you want to set variables in the dashboard)
   - Set worker runtime variables in worker settings (use "text" instead of "secret"):
      - `CLIENT_EMAIL`: This is the email associated with your GCP service account. You can find this in your service account's JSON key file.
      - `PRIVATE_KEY`: This is the private key associated with your GCP service account. You can find this in your service account's JSON key file.
      - `PROJECT`: This is the ID of your GCP project. You can find this in your service account's JSON key file.
      - `API_KEY`: This is a string that you define. It is used to authenticate requests to the worker.
   
Done! You can now access the API like this:

```bash
curl \
  'https://<your_worker_endpoint>.workers.dev/v1/models/gemini-2.0-flash-001:generateContent?key=<your_API_KEY_defined_above>' \
  -H 'Content-Type: application/json' \
  -X POST \
  --data-raw '{
    "contents": {
      "role": "user",
      "parts": [
        {
          "text": "hello"
        }
      ]
    }
  }'
```
