package staging

import (
	"context"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
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
		return nil, classifyBlobGetError(key, err)
	}
	return resp.Body, nil
}

// classifyBlobGetError turns "this blob does not exist" into *BlobMissingError and
// leaves every other failure exactly as it arrived.
//
// The narrowness is the point. Only BlobNotFound is mapped: ContainerNotFound is
// configuration and ServerBusy or a dial error is weather, and both of those still
// deserve the promotion worker's retry budget. Mapping on the 404 STATUS instead of
// the error code would have swept ContainerNotFound in with it and reported a missing
// layer digest for a misconfigured account.
func classifyBlobGetError(key string, err error) error {
	if bloberror.HasCode(err, bloberror.BlobNotFound) {
		// Wrapped, not replaced: the azcore error carries the request ID that Azure
		// support asks for, and discarding it would make a storage-side investigation
		// impossible.
		return fmt.Errorf("%w: %w", &BlobMissingError{Key: key}, err)
	}
	return err
}

func (a *azureBlobStore) Delete(ctx context.Context, key string) error {
	_, err := a.client.DeleteBlob(ctx, a.container, key, nil)
	return err
}
