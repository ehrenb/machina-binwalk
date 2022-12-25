import base64
import glob
import json
from pathlib import Path
import shutil

from machina.core.worker import Worker

import binwalk

class BinwalkAnalysis(Worker):
    types = [
        'jffs2'
    ]
    next_queues = ['Identifier']

    def __init__(self, *args, **kwargs):
        super(BinwalkAnalysis, self).__init__(*args, **kwargs)

    def callback(self, data, properties):
        data = json.loads(data)

        # resolve path
        target = self.get_binary_path(data['ts'], data['hashes']['md5'])
        self.logger.info(f"resolved path: {target}")

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
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    # if result.offset in module.extractor.output[result.file.path].carved:
                    #     print(f"Carved data from offset 0x%X to %s" % (result.offset, module.extractor.output[result.file.path].carved[result.offset])
                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        # print "Extracted %d files from offset 0x%X to '%s' using '%s'" % (len(module.extractor.output[result.file.path].extracted[result.offset].files),
                        #                                                                 result.offset,
                        #                                                                 module.extractor.output[result.file.path].extracted[result.offset].files[0],
                        #                                                                 module.extractor.output[result.file.path].extracted[result.offset].command)
                        files = module.extractor.output[result.file.path].extracted[result.offset].files

                        flattened_extracted_files = []
                        for f in files:

                            # if directory was extracted, recursively collect all files 
                            if Path(f).is_dir():
                                _files = [i for i in glob.glob(f'{f}/**/*', recursive=True) if Path(i).is_file()]
                                flattened_extracted_files.extend(_files)

                            # if file was extracted, just append it 
                            if Path(f).is_file():
                                flattened_extracted_files.append(f)

                        for f in flattened_extracted_files:
                            with open(f, 'rb') as f:
                                fdata = f.read()
                            
                            self.logger.info(f"publishing {f} to Identifier")

                            # Send each internal file to Identifier for analysis
                            data_encoded = base64.b64encode(fdata).decode()
                            body = json.dumps({
                                    "data": data_encoded,
                                    "origin": {
                                        "ts": data['ts'],
                                        "md5": data['hashes']['md5'],
                                        "id": data['id'], #I think this is the only field needed, we can grab the unique node based on id alone
                                        "type": data['type']}
                                    })
                            self.publish_next(body)
                            
                        # cleanup root directory
                        shutil.rmtree(files[0])