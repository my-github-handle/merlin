package staging

import (
	"context"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type azureBlobStore struct {
	client    *azblob.Client
	container string
}

// NewAzureBlobStore connects to Azure Blob Storage using a connection string.
func NewAzureBlobStore(connString, container string) (BlobStore, error) {
	client, err := azblob.NewClientFromConnectionString(connString, nil)
	if err != nil {
		return nil, fmt.Errorf("azure blob client: %w", err)
	}
	return &azureBlobStore{client: client, container: container}, nil
}

// NewAzureBlobStoreWithCredential connects to Blob using DefaultAzureCredential
// (AKS Workload Identity federated token in production). accountURL is the
// blob endpoint, e.g. https://<account>.blob.core.windows.net.
func NewAzureBlobStoreWithCredential(accountURL, container string) (BlobStore, error) {
	if accountURL == "" {
		return nil, fmt.Errorf("azure blob: account URL is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure default credential: %w", err)
	}
	client, err := azblob.NewClient(accountURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure blob client: %w", err)
	}
	return &azureBlobStore{client: client, container: container}, nil
}

func (a *azureBlobStore) Put(ctx context.Context, key string, r io.Reader) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	_, err = a.client.UploadBuffer(ctx, a.container, key, buf, nil)
	return err
}

func (a *azureBlobStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := a.client.DownloadStream(ctx, a.container, key, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (a *azureBlobStore) Delete(ctx context.Context, key string) error {
	_, err := a.client.DeleteBlob(ctx, a.container, key, nil)
	return err
}
