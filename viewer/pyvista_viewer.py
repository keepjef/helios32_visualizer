import numpy as np
import pyvista as pv


class PyVistaViewer:

    def __init__(self):

        self.plotter = pv.Plotter(
            window_size=(1600, 900)
        )

        self.plotter.set_background("black")

        self.plotter.add_axes()

    def show_frame(self, frame):

        xyz = frame[:, :3]

        intensity = frame[:, 3]

        print()
        print("POINTS =", len(xyz))
        print("MIN =", xyz.min(axis=0))
        print("MAX =", xyz.max(axis=0))
        print()

        cloud = pv.PolyData(xyz)

        cloud["intensity"] = intensity

        self.plotter.add_points(
            cloud,
            scalars="intensity",
            cmap="viridis",
            point_size=2,
            render_points_as_spheres=False
        )

        self.plotter.show()