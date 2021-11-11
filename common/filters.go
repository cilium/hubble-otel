package common

import (
	"fmt"

	flowV1 "github.com/cilium/cilium/api/v1/flow"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type IncludeFlowTypes []string

func (it IncludeFlowTypes) MakeFilters() []*flowV1.FlowFilter {
	filters := []*flowV1.EventTypeFilter{}
	if len(it) == 1 && (it[0] == "*" || it[0] == "all") {
		return []*flowV1.FlowFilter{}
	}
	for _, t := range it {
		filters = append(filters, &flowV1.EventTypeFilter{
			Type: int32(monitorAPI.MessageTypeNames[t]),
		})
	}
	return []*flowV1.FlowFilter{{
		EventType: filters,
	}}
}

func (it IncludeFlowTypes) Validate() error {
	for _, t := range it {
		if _, ok := monitorAPI.MessageTypeNames[t]; ok {
			continue
		}
		switch t {
		case "":
			return fmt.Errorf("type filter cannot be an empty string")

		case "*", "all":
			if len(it) != 1 {
				return fmt.Errorf("type filter %q can only be specified on its own", t)
			}
		default:
			return fmt.Errorf("unknown type filter %q", t)
		}
	}
	return nil
}
