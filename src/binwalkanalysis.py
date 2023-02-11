import base64
import glob
import json
from pathlib import Path
import shutil

from machina.core.worker import Worker

import binwalk

class BinwalkAnalysis(Worker):
    types = [
        'jffs2',
        'squashfs',
        'lzma',
        'cpio'
    ]
    next_queues = ['Identifier']

    def __init__(self, *args, **kwargs):
        super(BinwalkAnalysis, self).__init__(*args, **kwargs)

    def callback(self, data, properties):
        data = json.loads(data)

        # resolve path
        target = self.get_binary_path(data['ts'], data['hashes']['md5'])
        self.logger.info(f"resolved path: {target}")
        
        symlink_count = 0
        
        for module in binwalk.scan(
            target,
            '--run-as=root',
            '--matryoshka',
            '--depth=8',
            signature=True,
            quiet=True,
            extract=True):

            for result in module.results:
                if result.file.path in module.extractor.output:
                    if result.offset in module.extractor.output[result.file.path].extracted:

                        files = module.extractor.output[result.file.path].extracted[result.offset].files
                        flattened_extracted_files = []

                        for f in files:
                            # avoid duplicate of data through symlinks

                            # if directory was extracted, recursively collect all files
                            if Path(f).is_dir():
                                # _files = [i for i in glob.glob(f'{f}/**/*', recursive=True) if Path(i).is_file() and not Path(i).is_symlink()]
                                _files = []
                                for i in glob.glob(f'{f}/**/*', recursive=True):
                                    if Path(i).is_file():
                                        if Path(i).is_symlink():
                                            symlink_count += 1
                                            self.logger.debug(f"(in glob) file: {Path(i)} is a symlink, skipping")
                                        else:
                                            _files.append(i)
                                flattened_extracted_files.extend(_files)

                            # if file was extracted, just append it
                            if Path(f).is_file():
                                if Path(f).is_symlink():
                                    symlink_count += 1
                                    self.logger.debug(f"file: {Path(f)} is a symlink, skipping")
                                else:
                                    flattened_extracted_files.append(f)

                        for f in flattened_extracted_files:
                            with open(f, 'rb') as f:
                                fdata = f.read()
                            
                            self.logger.info(f"publishing {f} to Identifier")

                            # Send each extracted file to Identifier for analysis
                            data_encoded = base64.b64encode(fdata).decode()
                            body = json.dumps({
                                    "data": data_encoded,
                                    "origin": {
                                        "ts": data['ts'],
                                        "md5": data['hashes']['md5'],
                                        "uid": data['uid'],
                                        "type": data['type']}
                                    })
                            self.publish_next(body)
                            
                        # cleanup root directory
                        parent_dir = Path(files[0]).parent
                        shutil.rmtree(parent_dir)

        self.logger.debug(f"{symlink_count} symlinks skipped")