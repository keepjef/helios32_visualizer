from collections import OrderedDict

class FrameCache:
    def __init__(self, max_size=50):
        self.max_size = max_size
        self.cache = OrderedDict()

    def get(self, frame_id):
        if frame_id in self.cache:
            # Если кадр запросили, перемещаем его в конец (как самый "свежий")
            self.cache.move_to_end(frame_id)
            return self.cache[frame_id]
        return None

    def put(self, frame_id, frame_data):
        self.cache[frame_id] = frame_data
        # Если превысили лимит, удаляем самый старый элемент (сначала)
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)