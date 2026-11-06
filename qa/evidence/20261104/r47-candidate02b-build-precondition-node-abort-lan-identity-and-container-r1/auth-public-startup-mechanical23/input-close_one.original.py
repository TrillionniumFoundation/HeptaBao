    def close_one(self, row):
        if row['closeAttempted']:
            return row['closed']
        with self.signals.critical():
            row['closeAttempted'] = True
            try:
                os.close(row['fd'])
                row['closed'] = True
            except BaseException as error:
                row['closeError'] = error_projection(error)
                self.close_errors.append(row['closeError'])
        return row['closed']
