import numpy as np
import open3d as o3d


class Open3DViewer:

    def show_single_frame(self, frame):

        xyz = frame[:, :3]

        print()
        print("POINTS =", len(xyz))
        print("MIN =", xyz.min(axis=0))
        print("MAX =", xyz.max(axis=0))
        print()

        pcd = o3d.geometry.PointCloud()

        pcd.points = (
            o3d.utility.Vector3dVector(xyz)
        )

        colors = np.zeros(
            (len(xyz), 3),
            dtype=np.float32
        )

        colors[:, 0] = 1.0

        pcd.colors = (
            o3d.utility.Vector3dVector(colors)
        )

        bbox = pcd.get_axis_aligned_bounding_box()

        print("BBOX =", bbox)

        coordinate_frame = (
            o3d.geometry.TriangleMesh
            .create_coordinate_frame(
                size=5.0
            )
        )

        o3d.visualization.draw_geometries(
            [
                pcd,
                coordinate_frame
            ],
            window_name="Helios H70"
        )