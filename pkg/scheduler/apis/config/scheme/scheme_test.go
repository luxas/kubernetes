package scheme

import (
	"testing"
	"io/ioutil"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	kubeschedulerconfig "k8s.io/kubernetes/pkg/scheduler/apis/config"
	kubeschedulerconfigv1alpha1 "k8s.io/kube-scheduler/config/v1alpha1"
)

const sample = `
apiVersion: kubescheduler.config.k8s.io/v1alpha1
kind: KubeSchedulerConfiguration
schedulerName: foo
`

func TestReadConfigFileInto(t *testing.T) {
	tests := []struct{
		data string
		in runtime.Object
		out runtime.Object
		err bool
	}{
		{
			data: sample,
			emptyinternal: &kubeschedulerconfig.KubeSchedulerConfiguration{},
			out: &kubeschedulerconfigv1alpha1.KubeSchedulerConfiguration{
				SchedulerName: "foo",
			},
		},
	}
	for _, rt := range tests {
		t.Run("", func(t2 *testing.T){
			f, err := ioutil.TempFile("", "")
			if err != nil {
				t2.Fatal(err.Error())
			}
			f.WriteString(rt.data)
			f.Close()

			compare := rt.in.DeepCopyObject()
			if err := ReadConfigFileInto(f.Name(), rt.in); err != nil {
				t2.Error(err.Error())
			}
			Scheme.Default(rt.out)
			Scheme.Convert(rt.out, compare, nil)
			if !reflect.DeepEqual(rt.in, compare) {
				t2.Errorf("different: %#v %#v", rt.in, compare)
			}
		})
	}
}