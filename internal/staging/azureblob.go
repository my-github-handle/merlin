package staging

import (
	"context"
	"fmt"
	"io"

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
