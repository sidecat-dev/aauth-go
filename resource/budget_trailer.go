package resource

import (
	"errors"
	"net/http"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

// WriteStreamingBudgetHeader announces an AAuth-Budget trailer and sends the
// header instance. The header carries remaining and reserved and omits cost.
// Call it before WriteHeader. The fixed-price protected path does not use
// this helper; it commits the known cost before dispatch.
func WriteStreamingBudgetHeader(response http.ResponseWriter, feedback budgets.Feedback) error {
	if response == nil {
		return errors.New("resource: Budget response is required")
	}
	if _, reserved := feedback.Reserved(); !reserved {
		return errors.New("resource: streaming Budget header requires reserved")
	}
	if _, cost := feedback.Cost(); cost {
		return errors.New("resource: streaming Budget header must omit cost")
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		return err
	}
	response.Header().Set("Trailer", "AAuth-Budget")
	response.Header().Set("AAuth-Budget", formatted)
	return nil
}

// WriteStreamingBudgetTrailer sends the cost-only trailer. Call it after the
// response header has been written and the body is complete. The trailer does
// not restate remaining, reserved, unit, or decimals.
func WriteStreamingBudgetTrailer(response http.ResponseWriter, cost int64) error {
	if response == nil {
		return errors.New("resource: Budget response is required")
	}
	formatted, err := budgets.FormatTrailer(cost)
	if err != nil {
		return err
	}
	response.Header().Set("AAuth-Budget", formatted)
	return nil
}
