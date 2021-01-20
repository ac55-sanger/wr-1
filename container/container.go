/*******************************************************************************
 * Copyright (c) 2020 Genome Research Ltd.
 *
 * Authors: Sendu Bala <sb10@sanger.ac.uk>, Ashwini Chhipa <ac55@sanger.ac.uk>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  ******************************************************************************/

package container

// this file has functions for dealing with containers

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	fs "github.com/wtsi-ssg/wr/fs/filepath"
)

// OperationErr is supplied to Error to define the reasons for the failed operations.
type OperationErr string

// ErrContainer* are the reasons for the failed operations.
const (
	ErrContainerList  OperationErr = "Could not list the containers"
	ErrContainerStats OperationErr = "Could not get the container stats"
	ErrContainerKill  OperationErr = "Container could not be killed"
)

// OperatorErr records an error and a reason that caused it.
type OperatorErr struct {
	Type OperationErr // one of our OperationErr constants
	Err  error
}

// Error returns an error with the reason for a failed operation.
func (et OperatorErr) Error() string {
	msg := string(et.Type)
	if et.Err != nil {
		msg += " [" + et.Err.Error() + "]"
	}

	return msg
}

// Container struct represents a container type with id and name properties.
type Container struct {
	ID    string
	Names []string
}

// Stats struct represents a container stats type with memory and cpu properties.
type Stats struct {
	MemoryMB int
	CPUSec   int
}

// Interactor defines some methods to query containers.
type Interactor interface {
	ContainerList(ctx context.Context) ([]*Container, error)
	ContainerStats(ctx context.Context, containerID string) (*Stats, error)
	ContainerKill(ctx context.Context, containerID string) error
}

// Operator offers some methods for querying a container. You must use the
// NewOperator() method to make one, or the methods won't work.
type Operator struct {
	client             Interactor
	existingContainers map[string]bool
}

// NewOperator creates a new Operator, working on containers using the supplied Interactor.
// eg. to create an operator that can work with Docker containers:
/*
	import	(
		"github.com/docker/docker/client"
		"github.com/wtsi-wr/container/docker"
	)
	....
	{
		cli, err := client.NewEnvClient()

		dockerInterator := docker.NewInteractor(cli)

		dockerOperator := NewOperator(dockerInterator)

		cntrList, err := dockerOperator.GetCurrentContainers(ctx)
	}
	...
*/
func NewOperator(cntrInteractor Interactor) *Operator {
	return &Operator{
		client:             cntrInteractor,
		existingContainers: make(map[string]bool),
	}
}

// GetCurrentContainers returns current containers.
func (o *Operator) GetCurrentContainers(ctx context.Context) ([]*Container, error) {
	contnrList, err := o.client.ContainerList(ctx)
	if err != nil {
		return nil, &OperatorErr{Type: ErrContainerList, Err: err}
	}

	return contnrList, nil
}

// RememberCurrentContainerIDs calls GetCurrentContainers() and stores the
// results, for the benefit of a future GetNewContainerIDs() call.
func (o *Operator) RememberCurrentContainerIDs(ctx context.Context) error {
	curContainers, err := o.GetCurrentContainers(ctx)
	if err != nil {
		return err
	}

	for _, container := range curContainers {
		o.existingContainers[container.ID] = true
	}

	return nil
}

// GetNewContainers returns the list of all the new containers that now exists
// and weren't previously remembered by a RememberCurrentContainerIDs() call.
func (o *Operator) GetNewContainers(ctx context.Context) ([]*Container, error) {
	curContainers, err := o.GetCurrentContainers(ctx)
	if err != nil {
		return nil, err
	}

	var newContainers []*Container

	for _, container := range curContainers {
		if !o.existingContainers[container.ID] {
			newContainers = append(newContainers, container)
		}
	}

	return newContainers, nil
}

// GetNewContainerIDs returns the ids of all the containers that now exist
// and weren't previously remembered by a RememberCurrentContainerIDs() call.
func (o *Operator) GetNewContainerIDs(ctx context.Context) ([]string, error) {
	newContainers, err := o.GetNewContainers(ctx)
	if err != nil {
		return []string{}, err
	}

	newContainersIDs := make([]string, len(newContainers))

	for idx, container := range newContainers {
		newContainersIDs[idx] = container.ID
	}

	return newContainersIDs, nil
}

// GetNewContainerIDByName returns the id of the container with given name.
// Only new containers (those not remembered by the last RememberCurrentContainerIDs() call)
// are considered when searching for a container with that name.
func (o *Operator) GetNewContainerIDByName(ctx context.Context, name string) (string, error) {
	newContainers, err := o.GetNewContainers(ctx)
	if err != nil {
		return "", err
	}

	for _, cntr := range newContainers {
		if o.HasName(name, cntr) {
			return cntr.ID, nil
		}
	}

	return "", nil
}

// HasName checks if a given name is a valid container name.
func (o *Operator) HasName(name string, container *Container) bool {
	for _, cname := range container.Names {
		cname = strings.TrimPrefix(cname, "/")
		if cname == name {
			return true
		}
	}

	return false
}

// GetContainerIDByPath checks the file at the given path, and if the first line
// contains the ID of a container, that ID is returned.
//
// The path can contain globs: `?` to match any non-separator character and `*` to match
// any number of them. The first file to match the glob and also contain a valid id is the one used.
//
// In case the name is a relative file path, the second argument is the absolute path to the working
// directory where your container was created.
//
// This method is useful if container IDs are written to file, as they are eg. in the case of docker
// when using the --cidfile argument.
func (o *Operator) GetContainerIDByPath(ctx context.Context, path string, dir string) (string, error) {
	// if name is a relative file path, then create the absolute path with dir
	cidPath := fs.RelToAbsPath(path, dir)

	_, err := os.Stat(cidPath)
	if err == nil {
		return o.cidPathToID(ctx, cidPath)
	}

	// or it might be a file path with globs
	return o.cidPathGlobToID(ctx, cidPath)
}

// cidPathToID takes the absolute path to a file that exists, reads the first
// line, and checks that it is the ID of a current container. If so, returns
// that ID.
func (o *Operator) cidPathToID(ctx context.Context, cidPath string) (string, error) {
	fileContent, err := fs.ReadFile(cidPath)
	if err != nil {
		return "", err
	}

	id := strings.TrimSuffix(string(fileContent), "\n")

	ok, err := o.verifyID(ctx, id)
	if ok {
		return id, nil
	}

	return "", err
}

// verifyID checks if the given id is the ID of a current container.
func (o *Operator) verifyID(ctx context.Context, id string) (bool, error) {
	curContainers, err := o.GetCurrentContainers(ctx)
	if err != nil {
		return false, err
	}

	for _, container := range curContainers {
		if container.ID == id {
			return true, nil
		}
	}

	return false, nil
}

// cidPathGlobToID is like cidPathToID, but cidPath (which should not be
// relative) can contain standard glob characters such as ? and * and matching
// files will be checked until 1 contains a valid id, which gets returned.
func (o *Operator) cidPathGlobToID(ctx context.Context, cidGlobPath string) (string, error) {
	paths, err := filepath.Glob(cidGlobPath)
	if err != nil {
		return "", err
	}

	for _, path := range paths {
		id, err := o.cidPathToID(ctx, path)
		if err != nil {
			continue
		}

		if id != "" {
			return id, nil
		}
	}

	return "", nil
}

// ContainerStats asks the container for the current memory usage (RSS, in MB)
// and total CPU (in seconds) usage of the container with the given id.
func (o *Operator) ContainerStats(ctx context.Context, containerID string) (*Stats, error) {
	stats, err := o.client.ContainerStats(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// KillContainer kills the container with the given ID.
func (o *Operator) KillContainer(ctx context.Context, containerID string) error {
	return o.client.ContainerKill(ctx, containerID)
}
