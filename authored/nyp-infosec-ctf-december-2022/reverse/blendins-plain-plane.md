# Blendin's Plain Plane

| Difficulty | Points |
| ---------- | ------ |
| Easy       | 150    |

## Description

> The challenge lies ahead, in Blendin's plain plane, do you have what it takes to find the flag's reign?

{% file src="../../../.gitbook/assets/chall.py" %}

## Solution

### TL;DR

1. Add a for loop to create objects with the name of p1-p10

### Analysis

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
{% endtabs %}

Analyzing the code, we can see that this Python code is using the `bpy` library.

Upon [searching the library up](https://pypi.org/project/bpy/), we can see that this library utilizes the Blender API to modify objects in Blender.

We can download **Blender** and try to run this block of code to see what is returned to us. Open **Blender** and navigate to the **Scripting** tab, then paste the whole code into the terminal.

Going back to the **Layout** tab and going into **Object Mode** (press Tab key), we can see a huge cube is created. Upon deleting the cube, we see the incomplete flag.

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption><p>Empty Flag</p></figcaption></figure>

Clearly, we are missing some objects here. Nothing much we can do in Blender right now so let's head back to the code.

### Identifying A Pattern

Looking at the code closely, we can see a clear pattern in each paragraph of code.

Take these 2 paragraphs for example:

```python
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
```

The first paragraph just takes a Blender object named 'p3' and modifies the object's location and scale, adds another object at a specific location, names it 'c5', and resizes it.

The second paragraph then uses these two objects and does some operation on them. We do not need to understand this block of code, we can first try to create our objects.

Skimming through the code, we can see that the object names that the program uses are 'p1' to 'p10', 'c1' to 'c19', and 't1' and 't2'.

We see that 'c1' to 'c19' and 't1' and 't2' are created by the program itself, so we need to create our own 'p1' to 'p10' objects.

We can do so by adding a for loop to create these objects at the start of the program:

```python
for i in range(1,11):
    bpy.ops.mesh.primitive_plane_add()
    bpy.context.active_object.name = f'p{i}'
```

We can get the code to create and name an object through the `chall.py` itself, where `bpy.ops.mesh.primitive_plane_add()` (or you can also `primitive_cube_add`) adds a plane, and `bpy.context.active_object.name = '<name>'`gives the object a name.

Now we copy the whole script and paste into Blender and we should get our flag!

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption><p>Flag</p></figcaption></figure>

{% tabs %}
{% tab title="solve.py" %}
```python
import bpy,math

for i in range(1,11):
    bpy.ops.mesh.primitive_plane_add()
    bpy.context.active_object.name = f'p{i}'
    
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
{% endtabs %}

### Problems Faced

I was informed that there was certain issues when running the code in Blender.

I apologize as I did not account for the Blender version that the participants would be using, so I was using Blender 2.92 instead of the newest Blender 3.42 (at the time of creating this challenge).

Running in Python 3.42, the code returns an error due to missing `hide` attribute for the cubes created. So you had to hide the cubes manually or replace `hide` with `hide_viewport` to make the flag more visible.

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption><p>Error: Missing hide attribute</p></figcaption></figure>
