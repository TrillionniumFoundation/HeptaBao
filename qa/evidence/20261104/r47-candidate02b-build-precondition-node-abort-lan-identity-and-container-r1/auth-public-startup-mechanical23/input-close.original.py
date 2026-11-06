    def close(self):
        with self.signals.critical():
            for row in reversed(self.rows):
                self.close_one(row)
