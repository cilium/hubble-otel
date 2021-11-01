// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package batchprocessor // import "go.opentelemetry.io/collector/processor/batchprocessor"

import (
	"go.opentelemetry.io/collector/model/pdata"
)

// splitMetrics removes metrics from the input data and returns a new data of the specified size.
func splitMetrics(size int, src pdata.Metrics) pdata.Metrics {
	dataPoints := src.DataPointCount()
	if dataPoints <= size {
		return src
	}
	totalCopiedDataPoints := 0
	dest := pdata.NewMetrics()

	src.ResourceMetrics().RemoveIf(func(srcRs pdata.ResourceMetrics) bool {
		// If we are done skip everything else.
		if totalCopiedDataPoints == size {
			return false
		}

		// If it fully fits
		srcRsDataPointCount := resourceMetricsDataPointCount(srcRs)
		if (totalCopiedDataPoints + srcRsDataPointCount) <= size {
			totalCopiedDataPoints += srcRsDataPointCount
			srcRs.MoveTo(dest.ResourceMetrics().AppendEmpty())
			return true
		}

		destRs := dest.ResourceMetrics().AppendEmpty()
		srcRs.Resource().CopyTo(destRs.Resource())

		srcRs.InstrumentationLibraryMetrics().RemoveIf(func(srcIlm pdata.InstrumentationLibraryMetrics) bool {
			// If we are done skip everything else.
			if totalCopiedDataPoints == size {
				return false
			}

			// If possible to move all metrics do that.
			srcDataPointCount := metricSliceDataPointCount(srcIlm.Metrics())
			if size-totalCopiedDataPoints >= srcDataPointCount {
				totalCopiedDataPoints += srcDataPointCount
				srcIlm.MoveTo(destRs.InstrumentationLibraryMetrics().AppendEmpty())
				return true
			}

			destIlm := destRs.InstrumentationLibraryMetrics().AppendEmpty()
			srcIlm.InstrumentationLibrary().CopyTo(destIlm.InstrumentationLibrary())

			srcIlm.Metrics().RemoveIf(func(srcMetric pdata.Metric) bool {
				// If we are done skip everything else.
				if totalCopiedDataPoints == size {
					return false
				}
				// If the metric has more data points than free slots we should split it.
				copiedDataPoints, remove := splitMetric(srcMetric, destIlm.Metrics().AppendEmpty(), size-totalCopiedDataPoints)
				totalCopiedDataPoints += copiedDataPoints
				return remove
			})
			return false
		})
		return srcRs.InstrumentationLibraryMetrics().Len() == 0
	})

	return dest
}

// resourceMetricsDataPointCount calculates the total number of  data points.
func resourceMetricsDataPointCount(rs pdata.ResourceMetrics) (dataPointCount int) {
	for k := 0; k < rs.InstrumentationLibraryMetrics().Len(); k++ {
		dataPointCount += metricSliceDataPointCount(rs.InstrumentationLibraryMetrics().At(k).Metrics())
	}
	return
}

// metricSliceDataPointCount calculates the total number of  data points.
func metricSliceDataPointCount(ms pdata.MetricSlice) (dataPointCount int) {
	for k := 0; k < ms.Len(); k++ {
		dataPointCount += metricDataPointCount(ms.At(k))
	}
	return
}

// metricDataPointCount calculates the total number of  data points.
func metricDataPointCount(ms pdata.Metric) (dataPointCount int) {
	switch ms.DataType() {
	case pdata.MetricDataTypeGauge:
		dataPointCount = ms.Gauge().DataPoints().Len()
	case pdata.MetricDataTypeSum:
		dataPointCount = ms.Sum().DataPoints().Len()
	case pdata.MetricDataTypeHistogram:
		dataPointCount = ms.Histogram().DataPoints().Len()
	case pdata.MetricDataTypeSummary:
		dataPointCount = ms.Summary().DataPoints().Len()
	}
	return
}

// splitMetric removes metric points from the input data and moves data of the specified size to destination.
// Returns size of moved data and boolean describing, whether the metric should be removed from original slice.
func splitMetric(ms, dest pdata.Metric, size int) (int, bool) {
	if metricDataPointCount(ms) <= size {
		ms.MoveTo(dest)
		return metricDataPointCount(dest), true
	}

	dest.SetDataType(ms.DataType())
	dest.SetName(ms.Name())
	dest.SetDescription(ms.Description())
	dest.SetUnit(ms.Unit())

	switch ms.DataType() {
	case pdata.MetricDataTypeGauge:
		src := ms.Gauge().DataPoints()
		dst := dest.Gauge().DataPoints()
		dst.EnsureCapacity(size)
		i := 0
		src.RemoveIf(func(dp pdata.NumberDataPoint) bool {
			defer func() { i++ }()
			if i < size {
				dp.MoveTo(dst.AppendEmpty())
				return true
			}
			return false
		})
	case pdata.MetricDataTypeSum:
		src := ms.Sum().DataPoints()
		dst := dest.Sum().DataPoints()
		dst.EnsureCapacity(size)
		i := 0
		src.RemoveIf(func(dp pdata.NumberDataPoint) bool {
			defer func() { i++ }()
			if i < size {
				dp.MoveTo(dst.AppendEmpty())
				return true
			}
			return false
		})
	case pdata.MetricDataTypeHistogram:
		src := ms.Histogram().DataPoints()
		dst := dest.Histogram().DataPoints()
		dst.EnsureCapacity(size)
		i := 0
		src.RemoveIf(func(dp pdata.HistogramDataPoint) bool {
			defer func() { i++ }()
			if i < size {
				dp.MoveTo(dst.AppendEmpty())
				return true
			}
			return false
		})
	case pdata.MetricDataTypeSummary:
		src := ms.Summary().DataPoints()
		dst := dest.Summary().DataPoints()
		dst.EnsureCapacity(size)
		i := 0
		src.RemoveIf(func(dp pdata.SummaryDataPoint) bool {
			defer func() { i++ }()
			if i < size {
				dp.MoveTo(dst.AppendEmpty())
				return true
			}
			return false
		})
	}
	return size, false
}
