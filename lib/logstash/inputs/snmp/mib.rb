# encoding: utf-8

module LogStash
  class SnmpMibError < StandardError
  end

  class SnmpMib
    attr_reader :tree

    class Oid
      def self.parse(oid)
        oid.split(".").map(&:to_i)
      end
    end

    class BaseNode
      attr_reader :name, :childs

      def initialize(name)
        @name = name
        @childs = []
      end
    end

    class Node < BaseNode
      attr_reader :node_type, :module_name, :oid, :oid_path

      def initialize(node_type, name, module_name, oid)
        super(name)
        @node_type = node_type
        @module_name = module_name
        @oid = oid
        @oid_path = Oid.parse(oid)
      end
    end

    class Tree
      def initialize
        @root = BaseNode.new("root")
      end

      def add_node(node)
        warnings = []
        current = @root
        path = node.oid_path.dup

        # follow the OID path up until but not including the last node
        # and add intermediate missing nodes if needed
        last_node = path.pop
        path.each do |i|
          if current.childs[i].nil?
            current.childs[i] = BaseNode.new(i.to_s)
          end
          current = current.childs[i]
        end

        if current.childs[last_node] && current.childs[last_node].name != node.name
          warnings << "warning: overwriting MIB OID '#{node.oid}' and name '#{current.childs[last_node].name}' with new name '#{node.name}' from module '#{node.module_name}'"
        end
        current.childs[last_node] = node

        warnings
      end

      def map_oid(oid, strip_root = 0)
        path = Oid.parse(oid)

        result = []
        node = @root

        loop do
          break if path.empty?
          i = path.shift

          node = node.childs[i]

          if node.nil?
            result += path.unshift(i)
            break
          end
          result << node.name
        end

        result.drop(strip_root).join(".")
      end
    end

    def initialize
      @tree = Tree.new
    end

    # add a specific mib dic file or all mib dic files of the given directory to the current mib database
    # @param path [String] a file or directory path to mib dic file(s)
    # @return [Array] array of warning strings if any OID or name has been overwritten or the empty array when no warning
    def add_mib_path(path)
      dic_files = if ::File.directory?(path)
        Dir[::File.join(path, "*.dic")]
      elsif ::File.file?(path)
        [path]
      else
        raise(SnmpMibError, "file or directory path expected: #{path.to_s}")
      end

      warnings = []
      dic_files.each do |f|
        module_name, nodes = read_mib_dic(f)

        nodes.each do |k, v|
          warnings += @tree.add_node(Node.new(v["nodetype"], k, v["moduleName"], v["oid"]))
        end
      end

      warnings
    end

    # read and parse a mib dic file
    #
    # @param filename [String] file path of a mib dic file
    # @return [[String, Hash, Hash, Hash]] the 2-tuple of the mib module name and the complete nodes
    def read_mib_dic(filename)
      mib = eval_mib_dic(filename)
      raise(SnmpMibError, "invalid mib dic format for file #{filename}") unless mib
      module_name = mib["moduleName"]
      raise(SnmpMibError, "invalid mib dic format for file #{filename}") unless module_name
      nodes = mib["nodes"]
      raise(SnmpMibError, "no nodes defined in mib dic file #{filename}") unless nodes

      # name_hash is { mib-name => oid }
      # name_hash = {}
      # nodes.each { |k, v| name_hash[k] = v["oid"] }
      # if mib["notifications"]
      #   mib["notifications"].each { |k, v| name_hash[k] = v["oid"] }
      # end

      [module_name, nodes]
    end

    def map_oid(oid, strip_root = 0)
      @tree.map_oid(oid, strip_root)
    end

    private

    def eval_mib_dic(filename)
      mib_dic = IO.read(filename)
      mib_hash = mib_dic.
        gsub(':', '=>').                  # fix hash syntax
        gsub('(', '[').gsub(')', ']').    # fix tuple syntax
        sub('FILENAME =', 'filename =').  # get rid of constants
        sub('MIB =', 'mib =')

      mib = nil
      eval(mib_hash)
      mib
    rescue => e
      raise(SnmpMibError, "error parsing mib dic file: #{filename}, error: #{e.message}")
    end
  end
end
