# Blendin's Plain Plane

| Difficulty | Score |
| ---------- | ----- |
| Easy       | 150   |

## Description

> The challenge lies ahead, in Blendin's plain plane, do you have what it takes to find the flag's reign?

{% file src="../../../.gitbook/assets/chall.py" %}

{% tabs %}
{% tab title="First Tab" %}
```python
import bpy,math

bpy.ops.object.text_add(location=(0,-1,0))
bpy.context.active_object.name = 't1'
bpy.ops.transform.resize(value=(3,3,3))
bpy.ops.object.select_by_type(type='FONT')
bpy.context.active_object.data.body = 'NYP{'

bpy.data.objects['p1'].location = 8,0,0
bpy.data.objects['p1'].scale = 1, 2, 0.1
bpy.ops.mesh.primitive_cube_add(location=(7.800796,1.68747,0))
bpy.context.active_object.name = 'c1'
bpy.ops.transform.rotate(value=math.radians(19), orient_axis='Z')
bpy.ops.mesh.primitive_cube_add(location=(8.275793,-1.40951,0))
bpy.context.active_object.name = 'c2'
bpy.ops.transform.rotate(value=math.radians(19), orient_axis='Z')

b = bpy.data.objects["p1"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c1']
bpy.data.objects['c1'].hide = True
b = bpy.data.objects["p1"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c2']
bpy.data.objects['c2'].hide = True

bpy.data.objects['p2'].location = 10.5,0,0
bpy.data.objects['p2'].scale = 0.6,2,0.1
bpy.ops.mesh.primitive_cube_add(location=(9.8008,1.98747,0))
bpy.context.active_object.name = 'c3'
bpy.ops.transform.rotate(value=math.radians(130), orient_axis='Z')
bpy.ops.mesh.primitive_cube_add(location=(9.55518,-0.822348,0))
bpy.context.active_object.name = 'c4'
bpy.ops.transform.resize(value=(1, 1.350, 1))

b = bpy.data.objects["p2"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c3']
bpy.data.objects['c3'].hide = True
b = bpy.data.objects["p2"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c4']
bpy.data.objects['c4'].hide = True

bpy.data.objects['p3'].location = 13.5,0,0
bpy.data.objects['p3'].scale = 1.6, 2, 0.1
bpy.ops.mesh.primitive_cube_add(location=(14.3261 ,0.00787,0))
bpy.context.active_object.name = 'c5'
bpy.ops.transform.resize(value=(1.68, 1.29, 1))

b = bpy.data.objects["p3"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c5']
bpy.data.objects['c5'].hide = True

bpy.data.objects['p4'].location = 17.5,0,0
bpy.data.objects['p4'].scale = 1.3,2,0.1
bpy.ops.mesh.primitive_cube_add(location=(17.0119 ,0.861509,0))
bpy.context.active_object.name = 'c6'
bpy.ops.transform.resize(value=(1, 0.46, 1))
bpy.ops.mesh.primitive_cube_add(location=(17.0119 ,-0.783307,0))
bpy.context.active_object.name = 'c7'
bpy.ops.transform.resize(value=(1, 0.46, 1))

b = bpy.data.objects["p4"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c6']
bpy.data.objects['c6'].hide = True
b = bpy.data.objects["p4"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c7']
bpy.data.objects['c7'].hide = True

bpy.data.objects['p5'].location = 20.5,-1.7,0
bpy.data.objects['p5'].scale = 1.3,0.26,0.1

bpy.data.objects['p6'].location = 24.292,0,0
bpy.data.objects['p6'].scale = 1.57,1.82,0.1
bpy.ops.mesh.primitive_cube_add(location=(22.6334,1.78594,0))
bpy.context.active_object.name = 'c8'
bpy.ops.transform.resize(value=(1.31, 1.31, 1))
bpy.ops.transform.rotate(value=math.radians(132.4), orient_axis='Z')
bpy.ops.mesh.primitive_cube_add(location=(25.8606,1.0364,0))
bpy.context.active_object.name = 'c9'
bpy.ops.mesh.primitive_cube_add(location=(25.8606,-1.50369,0))
bpy.context.active_object.name = 'c10'
bpy.ops.mesh.primitive_cube_add(location=(23.05,-1.50369,0))
bpy.context.active_object.name = 'c11'
bpy.ops.mesh.primitive_cube_add(location=(23.8152,0.600365,1.19105))
bpy.context.active_object.name = 'c12'
bpy.ops.transform.rotate(value=math.radians(204), orient_axis='X')
bpy.ops.transform.rotate(value=math.radians(201), orient_axis='Y')
bpy.ops.transform.rotate(value=math.radians(272.3), orient_axis='Z')

b = bpy.data.objects["p6"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c8']
bpy.data.objects['c8'].hide = True
b = bpy.data.objects["p6"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c9']
bpy.data.objects['c9'].hide = True
b = bpy.data.objects["p6"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c10']
bpy.data.objects['c10'].hide = True
b = bpy.data.objects["p6"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c11']
bpy.data.objects['c11'].hide = True
b = bpy.data.objects["p6"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c12']
bpy.data.objects['c12'].hide = True

bpy.data.objects['p7'].location = 27.5,0,0
bpy.data.objects['p7'].scale = 1.3,2,0.1
bpy.ops.mesh.primitive_cube_add(location=(28.0119 ,0.861509,0))
bpy.context.active_object.name = 'c13'
bpy.ops.transform.resize(value=(1, 0.46, 1))
bpy.ops.mesh.primitive_cube_add(location=(26.7154 ,-0.783307,0))
bpy.context.active_object.name = 'c14'
bpy.ops.transform.resize(value=(1, 0.46, 1))

b = bpy.data.objects["p7"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c13']
bpy.data.objects['c13'].hide = True
b = bpy.data.objects["p7"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c14']
bpy.data.objects['c14'].hide = True

bpy.data.objects['p8'].location = 30.5,0,0
bpy.data.objects['p8'].scale = 1.3,2,0.1
bpy.ops.mesh.primitive_cube_add(location=(31.0119 ,0.861509,0))
bpy.context.active_object.name = 'c15'
bpy.ops.transform.resize(value=(1, 0.46, 1))
bpy.ops.mesh.primitive_cube_add(location=(29.7154 ,-0.783307,0))
bpy.context.active_object.name = 'c16'
bpy.ops.transform.resize(value=(1, 0.46, 1))

b = bpy.data.objects["p8"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c15']
bpy.data.objects['c15'].hide = True
b = bpy.data.objects["p8"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c16']
bpy.data.objects['c16'].hide = True

bpy.ops.mesh.primitive_cube_add(location=(0,0,-99))
bpy.ops.transform.resize(value=(100,100,100))

bpy.data.objects['p9'].location = 33.5,0,0
bpy.data.objects['p9'].scale = 1.3,2,0.1
bpy.ops.mesh.primitive_cube_add(location=(33.0119 ,0.861509,0))
bpy.context.active_object.name = 'c17'
bpy.ops.transform.resize(value=(1, 0.46, 1))
bpy.ops.mesh.primitive_cube_add(location=(33.0119 ,-0.783307,0))
bpy.context.active_object.name = 'c18'
bpy.ops.transform.resize(value=(1, 0.46, 1))

b = bpy.data.objects["p9"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c17']
bpy.data.objects['c17'].hide = True
b = bpy.data.objects["p9"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c18']
bpy.data.objects['c18'].hide = True

bpy.data.objects['p10'].location = 36.5,0,0
#bpy.ops.mesh.primitive_plane_add(location=(36.5,0,0))
#bpy.context.active_object.name = 'p10'
bpy.data.objects['p10'].scale = 1.3,2,0.1
bpy.ops.mesh.primitive_cube_add(location=(35.0723 ,-0.494759,0))
bpy.context.active_object.name = 'c19'
bpy.ops.transform.resize(value=(1, 1.58, 1))
bpy.ops.mesh.primitive_cube_add(location=(37.7523  ,-0.494759,0))
bpy.context.active_object.name = 'c20'
bpy.ops.transform.resize(value=(1, 1.58, 1))

b = bpy.data.objects["p10"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c19']
bpy.data.objects['c19'].hide = True
b = bpy.data.objects["p10"].modifiers.new(name="Boolean", type="BOOLEAN")
b.operation = "DIFFERENCE"
b.solver = "FAST"
b.object = bpy.data.objects['c20']
bpy.data.objects['c20'].hide = True

bpy.ops.object.text_add(location=(38,-1,0))
bpy.context.active_object.name = 't2'
bpy.ops.transform.resize(value=(3,3,3))
bpy.ops.object.select_by_type(type='FONT')
bpy.context.active_object.data.body = '}'

bpy.ops.object.mode_set(mode='EDIT')
```
{% endtab %}

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}

