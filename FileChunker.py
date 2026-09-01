import os

class Chunker():


    def __init__(self):

        self.chunks = []


    def splitter(self, file, chunk_size_MB):
        
        chunk_size_B = chunk_size_MB * 1024 * 1024

        file_dir, file_name = os.path.split(file)
        base_name, ext = os.path.splitext(file_name)

        part_num = 1

        with open(file, 'rb') as f_in:
            while True:
                chunk = f_in.read(chunk_size_B)

                if not chunk:
                    break

                chunk_name = os.path.join(file_dir, f"{base_name}_part_{part_num}{ext}")
                self.chunks.append(chunk_name)

                print(f"Creating chunk: {chunk_name}")
                with open(chunk_name, 'wb') as f_out:
                    f_out.write(chunk)
                
                part_num += 1
                
        print("\n----- File splitting complete! ✅ -----")

        return self.chunks


    def joiner(self, output_filename):

        if not self.chunks:
            print("\n----- No chunks found! ----- ")
            return
        
        print(f"\nRejoining files into: {output_filename}")

        with open(output_filename, "wb") as f_out:
            for chunk in self.chunks:
                with open(chunk, "rb") as f_in:
                    f_out.write(f_in.read())

        print("\n----- File joining complete! ✅ -----")
        

    def deleter(self):

        for chunk in self.chunks:
            os.remove(chunk)
        
        print("\n----- File deleting complete ! ✅ -----")


    