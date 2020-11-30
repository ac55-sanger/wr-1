/*******************************************************************************
 * Copyright (c) 2020 Genome Research Ltd.
 *
 * Authors: Ashwini Chhipa <ac55@sanger.ac.uk>
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

package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shirou/gopsutil/mem"
	. "github.com/smartystreets/goconvey/convey"
)

func TestUtilsFuncs(t *testing.T) {
	testmap := map[string]int{
		"k1": 10,
		"k2": 30,
		"k3": 5,
		"k4": 15,
	}

	testmapmap := map[string]map[string]int{
		"k1": {"ka1": 10,
			"ka2": 20,
		},
		"k2": {"ka1": 5,
			"ka2": 30,
		},
		"k3": {"ka1": 100,
			"ka2": 200,
		},
		"k4": {"ka1": 50,
			"ka2": 2,
		},
	}

	Convey("Test to check the createKeyvalFromMap for map[string]int", t, func() {
		testmapNil := map[string]int{}
		tnil := createKeyvalFromMap(testmapNil)
		So(len(tnil), ShouldEqual, 0)

		t := createKeyvalFromMap(testmap)
		So(len(t), ShouldEqual, len(testmap))
	})

	Convey("Test to check the sliceSort for map[string]int", t, func() {
		t := createKeyvalFromMap(testmap)
		t.sliceSort()
		So(t[0].Value, ShouldBeLessThanOrEqualTo, t[1].Value)
		So(t[1].Value, ShouldBeLessThanOrEqualTo, t[2].Value)
		So(t[2].Value, ShouldBeLessThanOrEqualTo, t[3].Value)
	})

	Convey("Test to check the sliceSortReverse for map[string]map[string]int", t, func() {
		t := createKeyvalFromMapOfMap(testmapmap, "ka1")
		t.sliceSortReverse()
		So(t[3].Value, ShouldBeLessThanOrEqualTo, t[2].Value)
		So(t[2].Value, ShouldBeLessThanOrEqualTo, t[1].Value)
		So(t[1].Value, ShouldBeLessThanOrEqualTo, t[0].Value)
	})

	Convey("Test to check the sortKeyvalstruct for map[string]int", t, func() {
		So(sortKeyvalstruct(0, []keyvalueStruct{}), ShouldBeEmpty)

		t := createKeyvalFromMap(testmap)
		t.sliceSort()
		So(sortKeyvalstruct(len(testmap), t), ShouldResemble, []string{"k3", "k1", "k4", "k2"})
	})

	Convey("Test to check the sorting of map by value", t, func() {
		So(SortMapKeysByIntValue(testmap), ShouldResemble, []string{"k3", "k1", "k4", "k2"})
		So(ReverseSortMapKeysByIntValue(testmap), ShouldResemble, []string{"k2", "k4", "k1", "k3"})
	})

	Convey("Test to check the sorting of map by map value with criterion", t, func() {
		criterion := "ka1"
		So(SortMapKeysByMapIntValue(testmapmap, criterion), ShouldResemble, []string{"k2", "k1", "k4", "k3"})

		criterion = "ka2"
		So(ReverseSortMapKeysByMapIntValue(testmapmap, criterion), ShouldResemble, []string{"k3", "k2", "k1", "k4"})
	})

	Convey("Test to check the DedupSortStrings function removing duplicates from a list and sorting it", t, func() {
		So(DedupSortStrings([]string{}), ShouldBeEmpty)

		testlist := []string{"k3", "k3", "k4", "k1"}

		So(DedupSortStrings(testlist), ShouldResemble, []string{"k1", "k3", "k4"})
	})

	Convey("Test to check the absolute path of a path starting with ~/", t, func() {
		So(TildaToHome(""), ShouldBeEmpty)

		home, herr := os.UserHomeDir()
		So(herr, ShouldEqual, nil)
		filepth := filepath.Join(home, "testing_absolute_path.text")
		file, err := os.Create(filepth)
		So(err, ShouldEqual, nil)
		defer file.Close()

		So(TildaToHome("~/testing_absolute_path.text"), ShouldEqual, filepth)
	})

	Convey("Test to check the PathToContent", t, func() {
		empContent, err := PathToContent("")
		So(err, ShouldNotBeNil)
		So(empContent, ShouldBeEmpty)

		home, herr := os.UserHomeDir()
		So(herr, ShouldEqual, nil)
		filepth := filepath.Join(home, "testing_pathtocontent.text")

		file, err := os.Create(filepth)
		So(err, ShouldEqual, nil)
		wrtn, err := file.WriteString("hello")
		So(err, ShouldEqual, nil)
		fmt.Printf("wrote %d bytes\n", wrtn)

		content, err := PathToContent(filepth)
		So(content, ShouldEqual, "hello")
		So(err, ShouldEqual, nil)

		content, err = PathToContent("random.txt")
		So(content, ShouldEqual, "")
		So(err, ShouldNotBeNil)
	})

	Convey("Test to check the ProcMeminfoMBs", t, func() {
		if runtime.GOOS == "solaris" {
			t.Skip("Only .Total is supported on Solaris")
		}

		v, err := mem.VirtualMemory()
		So(err, ShouldEqual, nil)

		So(v.Total, ShouldBeGreaterThan, 0)
		So(v.Available, ShouldBeGreaterThan, 0)
		So(v.Used, ShouldBeGreaterThan, 0)

		total := v.Used + v.Free + v.Buffers + v.Cached
		switch runtime.GOOS {
		case "windows":
			total = v.Used + v.Available
		case "darwin", "openbsd":
			total = v.Used + v.Free + v.Cached + v.Inactive
		case "freebsd":
			total = v.Used + v.Free + v.Cached + v.Inactive + v.Laundry
		}

		So(v.Total, ShouldEqual, total)

		v2, err2 := ProcMeminfoMBs()
		So(err2, ShouldEqual, nil)
		So(v2, ShouldEqual, bytesToMB(total))
	})
}
