package convert

import (
	"errors"
	"strings"

	basictypes "github.com/docker/docker/api/types"
	networktypes "github.com/docker/docker/api/types/network"
	types "github.com/docker/docker/api/types/swarm"
	swarmapi "github.com/docker/swarmkit/api"
	gogotypes "github.com/gogo/protobuf/types"
)

func networkAttachmentFromGRPC(na *swarmapi.NetworkAttachment) (types.NetworkAttachment, error) {
	if na != nil {
		n, err := networkFromGRPC(na.Network)
		if err != nil {
			return types.NetworkAttachment{}, err
		}
		return types.NetworkAttachment{
			Network:   n,
			Addresses: na.Addresses,
		}, nil
	}
	return types.NetworkAttachment{}, nil
}

func networkFromGRPC(n *swarmapi.Network) (types.Network, error) {
	if n != nil {
		cnmSpec := n.Spec.GetCNMCompat()
		if cnmSpec == nil {
			return types.Network{}, errors.New("Unexpected non-CNM network")
		}
		cnmState := n.GetCNMCompat()
		if cnmState == nil {
			return types.Network{}, errors.New("CNM network with no CNM state")
		}
		network := types.Network{
			ID: n.ID,
			Spec: types.NetworkSpec{
				IPv6Enabled: cnmSpec.Ipv6Enabled,
				Internal:    cnmSpec.Internal,
				Ingress:     cnmSpec.Ingress,
				Attachable:  cnmSpec.Attachable,
				IPAMOptions: ipamFromGRPC(cnmSpec.IPAM),
			},
			IPAMOptions: ipamFromGRPC(cnmState.IPAM),
		}

		// Meta
		network.Version.Index = n.Meta.Version.Index
		network.CreatedAt, _ = gogotypes.TimestampFromProto(n.Meta.CreatedAt)
		network.UpdatedAt, _ = gogotypes.TimestampFromProto(n.Meta.UpdatedAt)

		//Annotations
		network.Spec.Annotations = annotationsFromGRPC(n.Spec.Annotations)

		//DriverConfiguration
		if cnmSpec.DriverConfig != nil {
			network.Spec.DriverConfiguration = &types.Driver{
				Name:    cnmSpec.DriverConfig.Name,
				Options: cnmSpec.DriverConfig.Options,
			}
		}

		//DriverState
		if cnmState.DriverState != nil {
			network.DriverState = types.Driver{
				Name:    cnmState.DriverState.Name,
				Options: cnmState.DriverState.Options,
			}
		}

		return network, nil
	}
	return types.Network{}, nil
}

func ipamFromGRPC(i *swarmapi.IPAMOptions) *types.IPAMOptions {
	var ipam *types.IPAMOptions
	if i != nil {
		ipam = &types.IPAMOptions{}
		if i.Driver != nil {
			ipam.Driver.Name = i.Driver.Name
			ipam.Driver.Options = i.Driver.Options
		}

		for _, config := range i.Configs {
			ipam.Configs = append(ipam.Configs, types.IPAMConfig{
				Subnet:  config.Subnet,
				Range:   config.Range,
				Gateway: config.Gateway,
			})
		}
	}
	return ipam
}

func endpointSpecFromGRPC(es *swarmapi.EndpointSpec) *types.EndpointSpec {
	var endpointSpec *types.EndpointSpec
	if es != nil {
		endpointSpec = &types.EndpointSpec{}
		endpointSpec.Mode = types.ResolutionMode(strings.ToLower(es.Mode.String()))

		for _, portState := range es.Ports {
			endpointSpec.Ports = append(endpointSpec.Ports, swarmPortConfigToAPIPortConfig(portState))
		}
	}
	return endpointSpec
}

func endpointFromGRPC(e *swarmapi.Endpoint) types.Endpoint {
	endpoint := types.Endpoint{}
	if e != nil {
		if espec := endpointSpecFromGRPC(e.Spec); espec != nil {
			endpoint.Spec = *espec
		}

		for _, portState := range e.Ports {
			endpoint.Ports = append(endpoint.Ports, swarmPortConfigToAPIPortConfig(portState))
		}

		for _, v := range e.VirtualIPs {
			endpoint.VirtualIPs = append(endpoint.VirtualIPs, types.EndpointVirtualIP{
				NetworkID: v.NetworkID,
				Addr:      v.Addr})
		}

	}

	return endpoint
}

func swarmPortConfigToAPIPortConfig(portConfig *swarmapi.PortConfig) types.PortConfig {
	return types.PortConfig{
		Name:          portConfig.Name,
		Protocol:      types.PortConfigProtocol(strings.ToLower(swarmapi.PortConfig_Protocol_name[int32(portConfig.Protocol)])),
		PublishMode:   types.PortConfigPublishMode(strings.ToLower(swarmapi.PortConfig_PublishMode_name[int32(portConfig.PublishMode)])),
		TargetPort:    portConfig.TargetPort,
		PublishedPort: portConfig.PublishedPort,
	}
}

// BasicNetworkFromGRPC converts a grpc Network to a NetworkResource.
func BasicNetworkFromGRPC(n swarmapi.Network) (basictypes.NetworkResource, error) {
	cnmSpec := n.Spec.GetCNMCompat()
	if cnmSpec == nil {
		return basictypes.NetworkResource{}, errors.New("Unexpected non-CNM network")
	}
	cnmState := n.GetCNMCompat()
	if cnmState == nil {
		return basictypes.NetworkResource{}, errors.New("CNM network with no CNM state")
	}

	var ipam networktypes.IPAM
	if cnmSpec.IPAM != nil {
		if cnmSpec.IPAM.Driver != nil {
			ipam.Driver = cnmSpec.IPAM.Driver.Name
			ipam.Options = cnmSpec.IPAM.Driver.Options
		}
		ipam.Config = make([]networktypes.IPAMConfig, 0, len(cnmSpec.IPAM.Configs))
		for _, ic := range cnmSpec.IPAM.Configs {
			ipamConfig := networktypes.IPAMConfig{
				Subnet:     ic.Subnet,
				IPRange:    ic.Range,
				Gateway:    ic.Gateway,
				AuxAddress: ic.Reserved,
			}
			ipam.Config = append(ipam.Config, ipamConfig)
		}
	}

	nr := basictypes.NetworkResource{
		ID:         n.ID,
		Name:       n.Spec.Annotations.Name,
		Scope:      "swarm",
		EnableIPv6: cnmSpec.Ipv6Enabled,
		IPAM:       ipam,
		Internal:   cnmSpec.Internal,
		Attachable: cnmSpec.Attachable,
		Ingress:    cnmSpec.Ingress,
		Labels:     n.Spec.Annotations.Labels,
	}

	if cnmState.DriverState != nil {
		nr.Driver = cnmState.DriverState.Name
		nr.Options = cnmState.DriverState.Options
	}

	return nr, nil
}

// BasicNetworkCreateToGRPC converts a NetworkCreateRequest to a grpc NetworkSpec.
func BasicNetworkCreateToGRPC(create basictypes.NetworkCreateRequest) swarmapi.NetworkSpec {
	cnmSpec := &swarmapi.CNMNetworkSpec{
		DriverConfig: &swarmapi.Driver{
			Name:    create.Driver,
			Options: create.Options,
		},
		Ipv6Enabled: create.EnableIPv6,
		Internal:    create.Internal,
		Attachable:  create.Attachable,
		Ingress:     create.Ingress,
	}
	ns := swarmapi.NetworkSpec{
		Annotations: swarmapi.Annotations{
			Name:   create.Name,
			Labels: create.Labels,
		},
		Backend: &swarmapi.NetworkSpec_CNM{
			CNM: cnmSpec,
		},
	}
	if create.IPAM != nil {
		driver := create.IPAM.Driver
		if driver == "" {
			driver = "default"
		}
		cnmSpec.IPAM = &swarmapi.IPAMOptions{
			Driver: &swarmapi.Driver{
				Name:    driver,
				Options: create.IPAM.Options,
			},
		}
		ipamSpec := make([]*swarmapi.IPAMConfig, 0, len(create.IPAM.Config))
		for _, ipamConfig := range create.IPAM.Config {
			ipamSpec = append(ipamSpec, &swarmapi.IPAMConfig{
				Subnet:  ipamConfig.Subnet,
				Range:   ipamConfig.IPRange,
				Gateway: ipamConfig.Gateway,
			})
		}
		cnmSpec.IPAM.Configs = ipamSpec
	}
	return ns
}
